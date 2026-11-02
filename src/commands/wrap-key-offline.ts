import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import { acquireDeviceIdentityCoordinator } from "../infra/device-identity-coordinator.js";
import { readIdentityWriteReceipt } from "../infra/device-identity-store.activation.js";
import { preflightDeviceIdentityPopulationReadOnly } from "../infra/device-identity-store.js";
import {
  activateDeviceIdentityWriteGeneration,
  resolveDeviceIdentityWrappingOptions,
  rotateDeviceIdentityWrappingKey,
} from "../infra/device-identity.js";
import { defaultRuntime } from "../runtime.js";
import {
  CompositeKeyring,
  FileKeyring,
  preflightWrappingKeyProviderReadOnly,
} from "../security/keyring-provider.js";
import {
  openPreparedFileWrappingKey,
  resolveWrappingKeyVaultPath,
} from "../security/wrap-key-file-install.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";

type OfflineOptions = { receiptId: string; offline: boolean; json: boolean };
type RotationOptions = OfflineOptions & { keyId: string };
type Recovery = {
  ok: boolean;
  operation: "activate" | "rotate" | "recover";
  databaseState: "not-committed" | "current" | "superseded" | "unknown";
  generation?: number;
  keyId?: string;
  keyPath?: string;
  cliKeySelected?: boolean;
  gatewayRestartUnverified?: boolean;
  allRowsVerified?: boolean;
  checkedRows?: number;
  error?: string;
};

function emit(report: Recovery, json: boolean): boolean {
  if (json) {
    defaultRuntime.writeJson(report);
  } else {
    defaultRuntime.log(
      `Wrapping-key ${report.operation}: ${report.databaseState}; ${report.ok ? "offline key and rows verified" : "action required"}`,
    );
    if (report.keyId) {
      defaultRuntime.log(`Key ID: ${report.keyId}; generation: ${report.generation ?? "unknown"}`);
    }
    if (report.error) {
      defaultRuntime.error(report.error);
    }
    if (report.cliKeySelected === false && report.keyPath) {
      defaultRuntime.log(
        `Before restart, set OPENCLAW_WRAP_KEY_FILE=${report.keyPath} and OPENCLAW_WRAP_KEY_ID=${report.keyId}. Retain every old key for backups.`,
      );
    }
    if (report.gatewayRestartUnverified) {
      defaultRuntime.log(
        "The running gateway has not been verified. Restart it with the selected key and check identity health before resuming writers.",
      );
    }
  }
  return report.ok;
}

function assertOffline(offline: boolean): void {
  if (!offline) {
    throw new Error(
      "Stop all state writers and pass --offline before changing or recovering keys.",
    );
  }
}

async function verifyCurrentKey(keyId: string): Promise<{ checkedRows: number }> {
  const env = process.env;
  const provider = openPreparedFileWrappingKey(resolveStateDir(env), keyId);
  try {
    // A fresh provider tests the persisted bytes, not a rotation-time cache.
    provider.getActiveKey();
    const population = await preflightDeviceIdentityPopulationReadOnly({
      env,
      wrappingKeyProvider: provider,
    });
    if (!population.databaseExists || !population.rows.length || !population.allRowsVerified) {
      throw new Error("The new key cannot verify the complete identity population.");
    }
    return { checkedRows: population.rows.length };
  } finally {
    provider.release();
  }
}

async function runtimeSelectsCurrentKey(keyId: string): Promise<boolean> {
  const stateDir = resolveStateDir(process.env);
  const expected = path.join(resolveWrappingKeyVaultPath(stateDir), `${keyId}.b64`);
  const options = resolveDeviceIdentityWrappingOptions({ env: process.env }, false);
  const provider = options.wrappingKeyProvider;
  if (!(provider instanceof FileKeyring) || path.resolve(provider.getKeyPath()) !== expected) {
    return false;
  }
  try {
    if (provider.getActiveKey().keyId !== keyId) {
      return false;
    }
    const population = await preflightDeviceIdentityPopulationReadOnly(options);
    return population.databaseExists && population.rows.length > 0 && population.allRowsVerified;
  } finally {
    provider.release();
  }
}

function readReceipt(receiptId: string) {
  return readIdentityWriteReceipt(resolveOpenClawStateSqlitePath(process.env), receiptId);
}

export async function runWrapKeyActivate(opts: OfflineOptions): Promise<boolean> {
  try {
    assertOffline(opts.offline);
    const receipt = readReceipt(opts.receiptId);
    if (receipt?.generation === 1 && receipt.databaseState === "superseded") {
      return emit(
        {
          ok: false,
          operation: "activate",
          databaseState: "superseded",
          generation: 1,
          keyId: receipt.newWriteKeyId,
        },
        opts.json,
      );
    }
    const options = resolveDeviceIdentityWrappingOptions({ env: process.env }, false);
    if (!(options.wrappingKeyProvider instanceof FileKeyring)) {
      throw new Error("This offline command currently supports one active file key only.");
    }
    options.wrappingKeyProvider.getActiveKey();
    options.wrappingKeyProvider.assertCachedKeyStillInstalled();
    const population = await preflightDeviceIdentityPopulationReadOnly(options);
    if (!population.databaseExists || !population.rows.length || !population.allRowsVerified) {
      throw new Error("Activation requires an existing, nonempty, fully verified population.");
    }
    const provider = preflightWrappingKeyProviderReadOnly(options.wrappingKeyProvider);
    if (
      provider.status !== "verified" ||
      (receipt && provider.activeKeyId !== receipt.newWriteKeyId)
    ) {
      throw new Error("Activation key is not available under the committed key ID.");
    }
    const result = activateDeviceIdentityWriteGeneration(opts.receiptId, options);
    return emit(
      {
        ok: result.databaseState === "current",
        operation: "activate",
        databaseState: result.databaseState,
        generation: result.generation,
        keyId: provider.activeKeyId,
        gatewayRestartUnverified: true,
      },
      opts.json,
    );
  } catch {
    const receipt = (() => {
      try {
        return readReceipt(opts.receiptId);
      } catch {
        return null;
      }
    })();
    return emit(
      {
        ok: false,
        operation: "activate",
        databaseState: receipt?.databaseState ?? "unknown",
        ...(receipt ? { generation: receipt.generation, keyId: receipt.newWriteKeyId } : {}),
        error:
          "Activation unavailable. Keep writers stopped; inspect the receipt and full identity population before retrying.",
      },
      opts.json,
    );
  }
}

export async function runWrapKeyRotate(opts: RotationOptions): Promise<boolean> {
  try {
    assertOffline(opts.offline);
    const oldOptions = resolveDeviceIdentityWrappingOptions({ env: process.env }, false);
    const oldProvider = oldOptions.wrappingKeyProvider;
    if (!(oldProvider instanceof FileKeyring)) {
      throw new Error("This offline command currently supports one active file key only.");
    }
    const prepared = openPreparedFileWrappingKey(resolveStateDir(process.env), opts.keyId);
    const next = new CompositeKeyring([prepared, oldProvider]);
    let result: ReturnType<typeof rotateDeviceIdentityWrappingKey>;
    try {
      result = rotateDeviceIdentityWrappingKey({
        receiptId: opts.receiptId,
        targetKeyId: opts.keyId,
        oldKeyring: oldProvider,
        newKeyring: next,
        options: { env: process.env },
      });
    } finally {
      next.release();
    }
    if (result.databaseState !== "current") {
      return emit(
        {
          ok: false,
          operation: "rotate",
          databaseState: result.databaseState,
          generation: result.generation,
          keyId: opts.keyId,
          error: "This receipt was superseded; inspect the current generation before restart.",
        },
        opts.json,
      );
    }
    const verified = await verifyCurrentKey(opts.keyId);
    const current = readReceipt(opts.receiptId);
    if (!current || current.databaseState !== "current" || current.newWriteKeyId !== opts.keyId) {
      throw new Error("Rotation owner changed during post-commit verification.");
    }
    return emit(
      {
        ok: true,
        operation: "rotate",
        databaseState: "current",
        generation: current.generation,
        keyId: opts.keyId,
        keyPath: path.join(
          resolveWrappingKeyVaultPath(resolveStateDir(process.env)),
          `${opts.keyId}.b64`,
        ),
        cliKeySelected: false,
        gatewayRestartUnverified: true,
        allRowsVerified: true,
        checkedRows: verified.checkedRows,
      },
      opts.json,
    );
  } catch {
    const receipt = (() => {
      try {
        return readReceipt(opts.receiptId);
      } catch {
        return null;
      }
    })();
    return emit(
      {
        ok: false,
        operation: "rotate",
        databaseState: receipt?.databaseState ?? "unknown",
        ...(receipt ? { generation: receipt.generation, keyId: receipt.newWriteKeyId } : {}),
        error:
          "Rotation or post-commit verification failed. Keep all keys and writers stopped; run wrap-key recover with the same receipt ID.",
      },
      opts.json,
    );
  }
}

export async function runWrapKeyRecover(opts: RotationOptions): Promise<boolean> {
  try {
    assertOffline(opts.offline);
    const databasePath = resolveOpenClawStateSqlitePath(process.env);
    if (!fs.existsSync(databasePath)) {
      return emit({ ok: false, operation: "recover", databaseState: "not-committed" }, opts.json);
    }
    const coordinator = acquireDeviceIdentityCoordinator({ databasePath, env: process.env });
    try {
      const receipt = readReceipt(opts.receiptId);
      if (!receipt) {
        return emit({ ok: false, operation: "recover", databaseState: "not-committed" }, opts.json);
      }
      if (receipt.newWriteKeyId !== opts.keyId || receipt.generation < 2) {
        throw new Error("Receipt does not match this rotation target.");
      }
      if (receipt.databaseState === "superseded") {
        return emit(
          {
            ok: false,
            operation: "recover",
            databaseState: "superseded",
            generation: receipt.generation,
            keyId: opts.keyId,
          },
          opts.json,
        );
      }
      const verified = await verifyCurrentKey(opts.keyId);
      const cliKeySelected = await runtimeSelectsCurrentKey(opts.keyId);
      return emit(
        {
          ok: cliKeySelected,
          operation: "recover",
          databaseState: "current",
          generation: receipt.generation,
          keyId: opts.keyId,
          allRowsVerified: true,
          checkedRows: verified.checkedRows,
          cliKeySelected,
          gatewayRestartUnverified: true,
          ...(!cliKeySelected
            ? {
                keyPath: path.join(
                  resolveWrappingKeyVaultPath(resolveStateDir(process.env)),
                  `${opts.keyId}.b64`,
                ),
              }
            : {}),
        },
        opts.json,
      );
    } finally {
      coordinator.release();
    }
  } catch {
    const receipt = (() => {
      try {
        return readReceipt(opts.receiptId);
      } catch {
        return null;
      }
    })();
    return emit(
      {
        ok: false,
        operation: "recover",
        databaseState: receipt?.databaseState ?? "unknown",
        ...(receipt ? { generation: receipt.generation, keyId: receipt.newWriteKeyId } : {}),
        error:
          "Recovery could not verify the receipt, current provider and every identity. Keep all keys and writers stopped.",
      },
      opts.json,
    );
  }
}
