// Doctor-authorized retirement of the legacy Ed25519 primary identity JSON.
import path from "node:path";
import { root, type Root } from "@openclaw/fs-safe";
import {
  openExistingOpenClawStateDatabaseReadOnly,
  runOpenClawStateWriteTransaction,
} from "../state/openclaw-state-db.js";
import { acquireDeviceIdentityCoordinator } from "./device-identity-coordinator.js";
import {
  normalizeLegacyDeviceIdentity,
  type NormalizedLegacyDeviceIdentity,
} from "./device-identity-legacy.js";
import {
  DeviceIdentityStorageError,
  preflightDeviceIdentityPopulationReadOnly,
  readStoredDeviceIdentityReadOnly,
  upgradeDeviceIdentityPopulationWrapped,
  resolveDeviceIdentityStore,
  type DeviceIdentityStoreOptions,
  type StoredDeviceIdentity,
} from "./device-identity-store.js";
import { resolveDeviceIdentityWrappingOptions } from "./device-identity.js";
import { syncDirectoryIfSupported } from "./directory-durability.js";
import { formatErrorMessage } from "./errors.js";
import {
  moveLegacyIdentityPathWithoutOverwrite,
  MAX_LEGACY_IDENTITY_BYTES,
  restoreLegacyIdentityClaim,
} from "./state-migrations.device-identity-claim.js";
import {
  hasLegacyDeviceIdentityPath,
  repairInvalidCanonicalIdentity,
} from "./state-migrations.device-identity-repair.js";
import type { LegacyDeviceIdentityDetection } from "./state-migrations.device-identity.types.js";
import { withLegacyMigrationStateLock } from "./state-migrations.lock.js";
import {
  markLegacyMigrationSourceRemoved,
  recordLegacyMigrationReceipt,
  readLegacyMigrationReceiptFromDatabase,
  resolveLegacyMigrationSourceKey,
  type LegacyMigrationReceipt,
} from "./state-migrations.receipts.js";
import {
  legacyMigrationSourceSnapshotsMatch as snapshotsMatch,
  readLegacyMigrationSourceSnapshot,
  resolveLegacyMigrationRelativePath,
  type LegacyMigrationSourceSnapshot,
} from "./state-migrations.source-snapshot.js";
import type { MigrationMessages } from "./state-migrations.types.js";

const IDENTITY_KEY = "primary";
const MIGRATION_KIND = "legacy-device-identity-json";
const RETIREMENT_POLICY_VERSION = 1;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

type LegacySourceSnapshot = LegacyMigrationSourceSnapshot & {
  identity: NormalizedLegacyDeviceIdentity;
};

type CanonicalPqcResult = {
  identity: StoredDeviceIdentity;
  options: DeviceIdentityStoreOptions;
  repaired: boolean;
  rotated: boolean;
  upgraded: string[];
  pendingNative: string[];
};

type ArchiveResult = {
  action: "archived" | "removed-duplicate";
  archivePath: string;
};

export { detectLegacyDeviceIdentity } from "./state-migrations.device-identity-repair.js";

function relativeLegacyPath(stateDir: string, filePath: string): string {
  return resolveLegacyMigrationRelativePath(stateDir, filePath, "device identity", false);
}

async function readLegacySourceSnapshot(params: {
  stateRoot: Root;
  stateDir: string;
  sourcePath: string;
}): Promise<LegacySourceSnapshot> {
  const snapshot = await readLegacyBytesSnapshot(params);
  const identity = normalizeLegacyDeviceIdentity(JSON.parse(utf8Decoder.decode(snapshot.buffer)));
  if (!identity) {
    throw new Error("legacy device identity is invalid or unsupported");
  }
  return { ...snapshot, identity };
}

async function readLegacyBytesSnapshot(params: {
  stateRoot: Root;
  stateDir: string;
  sourcePath: string;
}): Promise<LegacyMigrationSourceSnapshot> {
  return await readLegacyMigrationSourceSnapshot({
    ...params,
    maxBytes: MAX_LEGACY_IDENTITY_BYTES,
    label: "device identity",
  });
}

function ensureCanonicalPqcIdentity(env: NodeJS.ProcessEnv): CanonicalPqcResult {
  const options = resolveDeviceIdentityWrappingOptions({ env, identityKey: IDENTITY_KEY }, true);
  if (!options.wrappingKeyProvider) {
    throw new DeviceIdentityStorageError(
      "A wrapping key provider is required before retiring a legacy device identity.",
    );
  }
  const result = upgradeDeviceIdentityPopulationWrapped(options, { createMissingPrimary: true });
  if (result.blocked.length) {
    throw new DeviceIdentityStorageError(
      "Identity population is blocked; no identities were changed. Restore its wrapping key or backup before retrying.",
    );
  }
  const identity = readStoredDeviceIdentityReadOnly(options);
  if (!identity) {
    throw new DeviceIdentityStorageError(
      "Primary identity was not durable after population upgrade.",
    );
  }
  return {
    identity,
    options,
    repaired: result.upgraded.includes(IDENTITY_KEY),
    rotated: result.createdPrimary,
    upgraded: result.upgraded,
    pendingNative: result.pendingNative,
  };
}

async function verifyCanonicalPqcIdentity(
  expectedDeviceId: string,
  options: DeviceIdentityStoreOptions,
): Promise<void> {
  const population = await preflightDeviceIdentityPopulationReadOnly(options);
  if (
    !population.databaseExists ||
    population.rows.some((row) => row.status === "blocked" || row.status === "needs-upgrade")
  ) {
    throw new DeviceIdentityStorageError(
      "Identity population changed or is blocked before legacy retirement; restore its wrapping key or backup before retrying.",
    );
  }
  const identity = readStoredDeviceIdentityReadOnly(options);
  if (!identity || identity.deviceId !== expectedDeviceId) {
    throw new Error("canonical ML-DSA device identity changed during legacy retirement");
  }
}

function recordRetirementReceipt(params: {
  env: NodeJS.ProcessEnv;
  sourcePath: string;
  snapshot: LegacySourceSnapshot;
  targetDeviceId: string;
}): void {
  const sourceKey = resolveLegacyMigrationSourceKey("device-identity-json", params.sourcePath);
  const runId = `${sourceKey}:${params.snapshot.sha256.slice(0, 16)}`;
  const now = Date.now();
  const reportJson = JSON.stringify({
    source: MIGRATION_KIND,
    policyVersion: RETIREMENT_POLICY_VERSION,
    target: "device_identities",
    identityKey: IDENTITY_KEY,
    legacyAlgorithm: "Ed25519",
    legacyDeviceId: params.snapshot.identity.deviceId,
    targetAlgorithm: "ML-DSA-65",
    targetDeviceId: params.targetDeviceId,
    authorizationTransferred: false,
    sourceSha256: params.snapshot.sha256,
    sourceSizeBytes: params.snapshot.size,
  });
  runOpenClawStateWriteTransaction(
    ({ db }) => {
      recordLegacyMigrationReceipt(db, {
        sourceKey,
        migrationKind: MIGRATION_KIND,
        sourcePath: params.sourcePath,
        targetTable: "device_identities",
        sourceSha256: params.snapshot.sha256,
        sourceSizeBytes: params.snapshot.size,
        sourceRecordCount: 1,
        runId,
        now,
        reportJson,
        upsert: true,
      });
    },
    { env: params.env },
    { operationLabel: "device-identity.legacy-retirement-receipt" },
  );
}

async function readRetirementReceipt(params: {
  env: NodeJS.ProcessEnv;
  sourcePath: string;
}): Promise<LegacyMigrationReceipt | null> {
  const database = await openExistingOpenClawStateDatabaseReadOnly({ env: params.env });
  if (!database) {
    return null;
  }
  try {
    return readLegacyMigrationReceiptFromDatabase(
      database.db,
      resolveLegacyMigrationSourceKey("device-identity-json", params.sourcePath),
    );
  } finally {
    database.walMaintenance.close();
  }
}

async function reconcileArchivedRetirement(params: {
  detected: LegacyDeviceIdentityDetection;
  stateRoot: Root;
  stateDir: string;
  env: NodeJS.ProcessEnv;
}): Promise<{ finalized: boolean; messages: MigrationMessages }> {
  const receipt = await readRetirementReceipt({
    env: params.env,
    sourcePath: params.detected.sourcePath,
  });
  if (!receipt || receipt.removedSource) {
    return { finalized: false, messages: { changes: [], warnings: [] } };
  }
  const changes: string[] = [];
  const warnings: string[] = [];
  try {
    const report: unknown = JSON.parse(receipt.reportJson);
    if (
      !report ||
      typeof report !== "object" ||
      !("source" in report) ||
      report.source !== MIGRATION_KIND ||
      !("targetDeviceId" in report) ||
      typeof report.targetDeviceId !== "string" ||
      !/^[a-f0-9]{64}$/.test(report.targetDeviceId) ||
      !("sourceSha256" in report) ||
      report.sourceSha256 !== receipt.sourceSha256 ||
      !("sourceSizeBytes" in report) ||
      typeof report.sourceSizeBytes !== "number" ||
      !Number.isSafeInteger(report.sourceSizeBytes) ||
      !("legacyDeviceId" in report) ||
      typeof report.legacyDeviceId !== "string" ||
      !/^[a-f0-9]{64}$/.test(report.legacyDeviceId)
    ) {
      throw new Error("retirement receipt is invalid");
    }
    const archiveDir = path.dirname(params.detected.sourcePath);
    const archiveBase = `${path.basename(params.detected.sourcePath)}.migrated`;
    const entries = await params.stateRoot.list(relativeLegacyPath(params.stateDir, archiveDir));
    const archiveNames = entries
      .map((name) => {
        const suffix = name.startsWith(`${archiveBase}.`) ? name.slice(archiveBase.length + 1) : "";
        const index = name === archiveBase ? 1 : Number(suffix);
        return index >= 1 &&
          index <= 10_000 &&
          (index === 1 ? name === archiveBase : suffix === String(index))
          ? { name, index }
          : null;
      })
      .filter((entry): entry is { name: string; index: number } => entry !== null)
      .toSorted((a, b) => a.index - b.index);
    for (const { name } of archiveNames) {
      const candidate = path.join(archiveDir, name);
      const snapshot = await readLegacyBytesSnapshot({
        stateRoot: params.stateRoot,
        stateDir: params.stateDir,
        sourcePath: candidate,
      });
      if (snapshot.sha256 === receipt.sourceSha256 && snapshot.size === report.sourceSizeBytes) {
        const archivedIdentity = await readLegacySourceSnapshot({
          stateRoot: params.stateRoot,
          stateDir: params.stateDir,
          sourcePath: candidate,
        });
        if (archivedIdentity.identity.deviceId !== report.legacyDeviceId) {
          throw new Error("archived Ed25519 identity differs from the retirement receipt");
        }
        await hardenPrivateFile({ ...params, filePath: candidate });
        const options = resolveDeviceIdentityWrappingOptions(
          { env: params.env, identityKey: IDENTITY_KEY },
          false,
        );
        const upgrade = upgradeDeviceIdentityPopulationWrapped(options);
        if (upgrade.blocked.length > 0) {
          throw new DeviceIdentityStorageError(
            "Identity population is blocked; restore its wrapping key or backup before finalizing legacy retirement.",
          );
        }
        changes.push(
          ...upgrade.upgraded.map(
            (key) => `Upgraded authenticated wrapping for device identity "${key}" in SQLite.`,
          ),
        );
        warnings.push(
          ...upgrade.pendingNative.map(
            (key) =>
              `Device identity "${key}" was preserved and still requires native Apple verification.`,
          ),
        );
        await verifyCanonicalPqcIdentity(report.targetDeviceId, options);
        for (const activePath of [
          params.detected.sourcePath,
          params.detected.claimPath,
          params.detected.nativeClaimPath,
        ]) {
          if (await params.stateRoot.exists(relativeLegacyPath(params.stateDir, activePath))) {
            throw new Error(
              "legacy device identity source or claim reappeared before finalization",
            );
          }
        }
        markLegacyMigrationSourceRemoved(
          receipt.sourceKey,
          params.env,
          "device-identity.legacy-retirement-reconcile",
        );
        return {
          finalized: true,
          messages: {
            changes: [
              ...changes,
              `Confirmed retired Ed25519 device identity archive → ${candidate}.`,
            ],
            warnings,
          },
        };
      }
    }
    throw new Error("no matching archive exists; restore the legacy source or archive from backup");
  } catch (error) {
    return {
      finalized: false,
      messages: {
        changes,
        warnings: [
          ...warnings,
          `Failed reconciling legacy device identity retirement: ${String(error)}`,
        ],
      },
    };
  }
}

async function hardenPrivateFile(params: {
  stateRoot: Root;
  stateDir: string;
  filePath: string;
  sync?: boolean;
}): Promise<void> {
  const opened = await params.stateRoot.open(relativeLegacyPath(params.stateDir, params.filePath));
  try {
    await opened.handle.chmod(0o600);
    if (params.sync) {
      await opened.handle.sync();
    }
  } finally {
    await opened.handle.close();
  }
}

async function firstArchivePath(params: {
  stateRoot: Root;
  stateDir: string;
  sourcePath: string;
  snapshot: LegacySourceSnapshot;
}): Promise<{ duplicate: boolean; path: string }> {
  for (let index = 1; index <= 10_000; index += 1) {
    const candidate =
      index === 1 ? `${params.sourcePath}.migrated` : `${params.sourcePath}.migrated.${index}`;
    if (!(await params.stateRoot.exists(relativeLegacyPath(params.stateDir, candidate)))) {
      return { duplicate: false, path: candidate };
    }
    await hardenPrivateFile({ ...params, filePath: candidate });
    const archived = await readLegacyBytesSnapshot({
      stateRoot: params.stateRoot,
      stateDir: params.stateDir,
      sourcePath: candidate,
    });
    if (params.snapshot.sha256 === archived.sha256 && params.snapshot.size === archived.size) {
      return { duplicate: true, path: candidate };
    }
  }
  throw new Error("too many retired device identity archives");
}

async function archiveClaim(params: {
  stateRoot: Root;
  stateDir: string;
  sourcePath: string;
  claimPath: string;
  snapshot: LegacySourceSnapshot;
}): Promise<ArchiveResult> {
  if (await params.stateRoot.exists(relativeLegacyPath(params.stateDir, params.sourcePath))) {
    throw new Error("legacy device identity source reappeared during retirement");
  }
  const finalClaim = await readLegacySourceSnapshot({
    stateRoot: params.stateRoot,
    stateDir: params.stateDir,
    sourcePath: params.claimPath,
  });
  if (!snapshotsMatch(params.snapshot, finalClaim)) {
    throw new Error("legacy device identity claim changed after ML-DSA identity creation");
  }

  const archive = await firstArchivePath({ ...params, snapshot: finalClaim });
  await hardenPrivateFile({ ...params, filePath: params.claimPath });
  if (!archive.duplicate) {
    // Keep the authoritative claim recoverable until the archive is verified.
    await params.stateRoot.create(
      relativeLegacyPath(params.stateDir, archive.path),
      finalClaim.buffer,
      { mode: 0o600, mkdir: false },
    );
  }
  await hardenPrivateFile({ ...params, filePath: archive.path, sync: true });
  const archived = await readLegacyBytesSnapshot({
    stateRoot: params.stateRoot,
    stateDir: params.stateDir,
    sourcePath: archive.path,
  });
  if (finalClaim.sha256 !== archived.sha256 || finalClaim.size !== archived.size) {
    throw new Error("archived Ed25519 device identity does not match the claimed source");
  }
  const retainedClaim = await readLegacySourceSnapshot({
    stateRoot: params.stateRoot,
    stateDir: params.stateDir,
    sourcePath: params.claimPath,
  });
  if (!snapshotsMatch(finalClaim, retainedClaim)) {
    throw new Error("legacy device identity claim changed during archival");
  }
  if (await params.stateRoot.exists(relativeLegacyPath(params.stateDir, params.sourcePath))) {
    throw new Error("legacy device identity source reappeared during archival");
  }
  await syncDirectoryIfSupported(
    await params.stateRoot.resolve(relativeLegacyPath(params.stateDir, path.dirname(archive.path))),
  );
  await params.stateRoot.remove(relativeLegacyPath(params.stateDir, params.claimPath));
  return {
    action: archive.duplicate ? "removed-duplicate" : "archived",
    archivePath: archive.path,
  };
}

async function retireWithExclusiveStateOwnership(params: {
  detected: LegacyDeviceIdentityDetection;
  stateRoot: Root;
  stateDir: string;
  env: NodeJS.ProcessEnv;
  beforeClaim?: (sourcePath: string) => void;
  beforeCleanup?: () => void;
  afterReceiptRecorded?: () => void;
  afterArchiveVerified?: () => void;
}): Promise<MigrationMessages> {
  if (
    await params.stateRoot.exists(
      relativeLegacyPath(params.stateDir, params.detected.nativeClaimPath),
    )
  ) {
    return {
      changes: [],
      warnings: [
        "Native device identity import is pending; restart the native app before running Doctor.",
      ],
    };
  }

  const hasSource = await params.stateRoot.exists(
    relativeLegacyPath(params.stateDir, params.detected.sourcePath),
  );
  let hasClaim = await params.stateRoot.exists(
    relativeLegacyPath(params.stateDir, params.detected.claimPath),
  );
  if (hasSource && hasClaim) {
    const restoreError = await restoreLegacyIdentityClaim({ ...params, ...params.detected });
    if (restoreError) {
      return {
        changes: [],
        warnings: [`Failed retiring legacy device identity: ${restoreError}`],
      };
    }
    hasClaim = false;
  }
  const activePath = hasSource
    ? params.detected.sourcePath
    : hasClaim
      ? params.detected.claimPath
      : null;
  if (!activePath) {
    return (await reconcileArchivedRetirement(params)).messages;
  }

  let snapshot: LegacySourceSnapshot;
  try {
    snapshot = await readLegacySourceSnapshot({
      stateRoot: params.stateRoot,
      stateDir: params.stateDir,
      sourcePath: activePath,
    });
  } catch (error) {
    return {
      changes: [],
      warnings: [`Failed reading legacy device identity: ${String(error)}`],
    };
  }

  if (activePath === params.detected.sourcePath) {
    try {
      params.beforeClaim?.(params.detected.sourcePath);
      const claimed = await moveLegacyIdentityPathWithoutOverwrite({
        ...params,
        sourcePath: params.detected.sourcePath,
        targetPath: params.detected.claimPath,
        snapshot,
      });
      snapshot = { ...claimed, identity: snapshot.identity };
    } catch (error) {
      const restoreError = await restoreLegacyIdentityClaim({ ...params, ...params.detected });
      return {
        changes: [],
        warnings: [
          `Failed retiring legacy device identity: ${String(error)}${restoreError ? `; restore failure: ${restoreError}` : ""}`,
        ],
      };
    }
  }

  // SQLite commits before filesystem retirement. Retain those facts even when
  // later cleanup fails, including approval guidance for a newly created device.
  let committed: MigrationMessages = { changes: [], warnings: [] };
  try {
    const canonical = ensureCanonicalPqcIdentity(params.env);
    const identityChange = canonical.rotated
      ? "Generated a new ML-DSA primary device identity."
      : canonical.repaired
        ? "Upgraded authenticated wrapping for the existing ML-DSA primary device identity."
        : "Preserved the existing ML-DSA primary device identity.";
    committed = {
      changes: [
        identityChange,
        ...canonical.upgraded
          .filter((key) => key !== IDENTITY_KEY)
          .map((key) => `Upgraded authenticated wrapping for device identity "${key}" in SQLite.`),
      ],
      warnings: canonical.pendingNative.map(
        (key) =>
          `Device identity "${key}" was preserved and still requires native Apple verification.`,
      ),
      notices: canonical.rotated
        ? [
            "The retired Ed25519 device authorization was not transferred; approve the new ML-DSA device identity.",
          ]
        : [
            "The retired Ed25519 device authorization was not transferred; the existing ML-DSA identity was preserved.",
          ],
    };
    params.beforeCleanup?.();
    await verifyCanonicalPqcIdentity(canonical.identity.deviceId, canonical.options);
    recordRetirementReceipt({
      env: params.env,
      sourcePath: params.detected.sourcePath,
      snapshot,
      targetDeviceId: canonical.identity.deviceId,
    });
    params.afterReceiptRecorded?.();
    await verifyCanonicalPqcIdentity(canonical.identity.deviceId, canonical.options);
    const archived = await archiveClaim({
      ...params,
      sourcePath: params.detected.sourcePath,
      claimPath: params.detected.claimPath,
      snapshot,
    });
    params.afterArchiveVerified?.();
    const finalized = await reconcileArchivedRetirement(params);
    if (!finalized.finalized) {
      throw new Error(
        finalized.messages.warnings.join("; ") || "retirement receipt was not finalized",
      );
    }

    const archiveChange =
      archived.action === "archived"
        ? `Archived retired Ed25519 device identity → ${archived.archivePath}.`
        : `Removed duplicate retired Ed25519 source; archive remains at ${archived.archivePath}.`;
    return {
      ...committed,
      changes: [...committed.changes, archiveChange],
    };
  } catch (error) {
    const restoreError = await restoreLegacyIdentityClaim({ ...params, ...params.detected });
    return {
      ...committed,
      warnings: [
        ...committed.warnings,
        `Failed retiring legacy device identity: ${String(error)}${restoreError ? `; restore failure: ${restoreError}` : ""}`,
      ],
    };
  }
}

/** Retire Ed25519 state and create or preserve the authoritative ML-DSA identity. */
export async function migrateLegacyDeviceIdentity(params: {
  detected: LegacyDeviceIdentityDetection;
  stateDir: string;
  env?: NodeJS.ProcessEnv;
  doctorOnlyStateMigrations?: boolean;
  beforeClaim?: (sourcePath: string) => void;
  beforeCleanup?: () => void;
  afterReceiptRecorded?: () => void;
  afterArchiveVerified?: () => void;
}): Promise<MigrationMessages> {
  if (params.doctorOnlyStateMigrations !== true) {
    return { changes: [], warnings: [] };
  }
  let pendingRetirement = false;
  if (!params.detected.hasLegacy) {
    try {
      const receipt = await readRetirementReceipt({
        env: { ...(params.env ?? process.env), OPENCLAW_STATE_DIR: params.stateDir },
        sourcePath: params.detected.sourcePath,
      });
      if ((!receipt || receipt.removedSource) && !params.detected.hasInvalidCanonical) {
        return { changes: [], warnings: [] };
      }
      pendingRetirement = receipt?.removedSource === false;
    } catch (error) {
      return {
        changes: [],
        warnings: [`Failed reading legacy device identity retirement receipt: ${String(error)}`],
      };
    }
  }
  let identityCoordinator: ReturnType<typeof acquireDeviceIdentityCoordinator> | undefined;
  return await withLegacyMigrationStateLock({
    stateDir: params.stateDir,
    env: params.env,
    label: "legacy device identity",
    releaseLabel: "Device identity",
    errorLabel: "Failed reading legacy device identity state",
    beforeRelease: () => identityCoordinator?.release(),
    run: async (env) => {
      try {
        identityCoordinator = acquireDeviceIdentityCoordinator({
          databasePath: resolveDeviceIdentityStore({ env, identityKey: IDENTITY_KEY }).databasePath,
          env,
        });
      } catch (error) {
        return {
          changes: [],
          warnings: [
            `Failed retiring legacy device identity: identity state is busy (${formatErrorMessage(error)}).`,
          ],
        };
      }
      if (hasLegacyDeviceIdentityPath(params.detected) || pendingRetirement) {
        const stateRoot = await root(params.stateDir, {
          hardlinks: "reject",
          maxBytes: MAX_LEGACY_IDENTITY_BYTES,
          symlinks: "reject",
        });
        return await retireWithExclusiveStateOwnership({ ...params, env, stateRoot });
      }
      return params.detected.hasInvalidCanonical
        ? repairInvalidCanonicalIdentity(env)
        : { changes: [], warnings: [] };
    },
  });
}
