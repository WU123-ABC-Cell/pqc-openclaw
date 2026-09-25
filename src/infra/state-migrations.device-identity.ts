// Doctor-authorized retirement of the legacy Ed25519 primary identity JSON.
import { root, type Root } from "@openclaw/fs-safe";
import { runOpenClawStateWriteTransaction } from "../state/openclaw-state-db.js";
import { acquireDeviceIdentityCoordinator } from "./device-identity-coordinator.js";
import {
  normalizeLegacyDeviceIdentity,
  type NormalizedLegacyDeviceIdentity,
} from "./device-identity-legacy.js";
import {
  DeviceIdentityStorageError,
  ensureStoredDeviceIdentityWrapped,
  generateStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  repairInvalidStoredDeviceIdentity,
  resolveDeviceIdentityStore,
  type DeviceIdentityStoreOptions,
  type StoredDeviceIdentity,
} from "./device-identity-store.js";
import { resolveDeviceIdentityWrappingOptions } from "./device-identity.js";
import { formatErrorMessage } from "./errors.js";
import {
  hasLegacyDeviceIdentityPath,
  repairInvalidCanonicalIdentity,
} from "./state-migrations.device-identity-repair.js";
import type { LegacyDeviceIdentityDetection } from "./state-migrations.device-identity.types.js";
import { withLegacyMigrationStateLock } from "./state-migrations.lock.js";
import {
  markLegacyMigrationSourceRemoved,
  recordLegacyMigrationReceipt,
  resolveLegacyMigrationSourceKey,
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
const MAX_LEGACY_IDENTITY_BYTES = 128 * 1024;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

type LegacySourceSnapshot = LegacyMigrationSourceSnapshot & {
  identity: NormalizedLegacyDeviceIdentity;
};

type CanonicalPqcResult = {
  identity: StoredDeviceIdentity;
  options: DeviceIdentityStoreOptions;
  repaired: boolean;
  rotated: boolean;
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
  const result = repairInvalidStoredDeviceIdentity(
    generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
    options,
  );
  const wrapped = ensureStoredDeviceIdentityWrapped(options);
  return {
    identity: wrapped.identity,
    options,
    repaired: result.repaired || wrapped.rewrapped,
    rotated: result.rotated,
  };
}

function verifyCanonicalPqcIdentity(
  expectedDeviceId: string,
  options: DeviceIdentityStoreOptions,
): void {
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
}): string {
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
  return sourceKey;
}

async function hardenPrivateFile(params: {
  stateRoot: Root;
  stateDir: string;
  filePath: string;
}): Promise<void> {
  const opened = await params.stateRoot.open(relativeLegacyPath(params.stateDir, params.filePath));
  try {
    await opened.handle.chmod(0o600);
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
  if (archive.duplicate) {
    await hardenPrivateFile({ ...params, filePath: archive.path });
    await params.stateRoot.remove(relativeLegacyPath(params.stateDir, params.claimPath));
    return { action: "removed-duplicate", archivePath: archive.path };
  }

  await params.stateRoot.move(
    relativeLegacyPath(params.stateDir, params.claimPath),
    relativeLegacyPath(params.stateDir, archive.path),
  );
  await hardenPrivateFile({ ...params, filePath: archive.path });
  const archived = await readLegacyBytesSnapshot({
    stateRoot: params.stateRoot,
    stateDir: params.stateDir,
    sourcePath: archive.path,
  });
  if (finalClaim.sha256 !== archived.sha256 || finalClaim.size !== archived.size) {
    throw new Error("archived Ed25519 device identity does not match the claimed source");
  }
  return { action: "archived", archivePath: archive.path };
}

async function restoreClaim(params: {
  stateRoot: Root;
  stateDir: string;
  sourcePath: string;
  claimPath: string;
}): Promise<string | null> {
  try {
    if (!(await params.stateRoot.exists(relativeLegacyPath(params.stateDir, params.claimPath)))) {
      return null;
    }
    if (await params.stateRoot.exists(relativeLegacyPath(params.stateDir, params.sourcePath))) {
      return `source path already exists: ${params.sourcePath}`;
    }
    await params.stateRoot.move(
      relativeLegacyPath(params.stateDir, params.claimPath),
      relativeLegacyPath(params.stateDir, params.sourcePath),
    );
    return null;
  } catch (error) {
    return String(error);
  }
}

async function retireWithExclusiveStateOwnership(params: {
  detected: LegacyDeviceIdentityDetection;
  stateRoot: Root;
  stateDir: string;
  env: NodeJS.ProcessEnv;
  beforeClaim?: (sourcePath: string) => void;
  beforeCleanup?: () => void;
  afterReceiptMarked?: () => void;
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
  const hasClaim = await params.stateRoot.exists(
    relativeLegacyPath(params.stateDir, params.detected.claimPath),
  );
  if (hasSource && hasClaim) {
    return {
      changes: [],
      warnings: [
        "Failed retiring legacy device identity: source and interrupted claim both exist.",
      ],
    };
  }
  const activePath = hasSource
    ? params.detected.sourcePath
    : hasClaim
      ? params.detected.claimPath
      : null;
  if (!activePath) {
    return { changes: [], warnings: [] };
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
      await params.stateRoot.move(
        relativeLegacyPath(params.stateDir, params.detected.sourcePath),
        relativeLegacyPath(params.stateDir, params.detected.claimPath),
      );
      const claimed = await readLegacySourceSnapshot({
        stateRoot: params.stateRoot,
        stateDir: params.stateDir,
        sourcePath: params.detected.claimPath,
      });
      if (!snapshotsMatch(snapshot, claimed)) {
        throw new Error("legacy device identity changed before Doctor could claim it");
      }
      snapshot = claimed;
    } catch (error) {
      const restoreError = await restoreClaim({ ...params, ...params.detected });
      return {
        changes: [],
        warnings: [
          `Failed retiring legacy device identity: ${String(error)}${restoreError ? `; restore failure: ${restoreError}` : ""}`,
        ],
      };
    }
  }

  try {
    const canonical = ensureCanonicalPqcIdentity(params.env);
    verifyCanonicalPqcIdentity(canonical.identity.deviceId, canonical.options);
    const sourceKey = recordRetirementReceipt({
      env: params.env,
      sourcePath: params.detected.sourcePath,
      snapshot,
      targetDeviceId: canonical.identity.deviceId,
    });
    params.beforeCleanup?.();
    verifyCanonicalPqcIdentity(canonical.identity.deviceId, canonical.options);
    markLegacyMigrationSourceRemoved(
      sourceKey,
      params.env,
      "device-identity.legacy-retirement-complete",
    );
    params.afterReceiptMarked?.();
    const archived = await archiveClaim({
      ...params,
      sourcePath: params.detected.sourcePath,
      claimPath: params.detected.claimPath,
      snapshot,
    });

    const identityChange = canonical.rotated
      ? "Generated a new ML-DSA primary device identity."
      : canonical.repaired
        ? "Repaired the existing ML-DSA primary device identity metadata."
        : "Preserved the existing ML-DSA primary device identity.";
    const archiveChange =
      archived.action === "archived"
        ? `Archived retired Ed25519 device identity → ${archived.archivePath}.`
        : `Removed duplicate retired Ed25519 source; archive remains at ${archived.archivePath}.`;
    return {
      changes: [identityChange, archiveChange],
      warnings: [],
      notices: canonical.rotated
        ? [
            "The retired Ed25519 device authorization was not transferred; approve the new ML-DSA device identity.",
          ]
        : [
            "The retired Ed25519 device authorization was not transferred; the existing ML-DSA identity was preserved.",
          ],
    };
  } catch (error) {
    const restoreError = await restoreClaim({ ...params, ...params.detected });
    return {
      changes: [],
      warnings: [
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
  afterReceiptMarked?: () => void;
}): Promise<MigrationMessages> {
  if (!params.detected.hasLegacy && !params.detected.hasInvalidCanonical) {
    return { changes: [], warnings: [] };
  }
  if (params.doctorOnlyStateMigrations !== true) {
    return { changes: [], warnings: [] };
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
      if (hasLegacyDeviceIdentityPath(params.detected)) {
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
