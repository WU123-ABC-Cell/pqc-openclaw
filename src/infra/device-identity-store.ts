// Canonical SQLite storage for the fork's post-quantum device identities.
//
// The PQC fork replaces Ed25519 with ML-DSA-65 (FIPS 204, parameter set 6).
// Key material is stored as base64url-encoded raw bytes inside the
// MLDSA65-PUBLIC-KEY: / MLDSA65-SECRET-KEY: prefixed format, in two places:
//
//  1. The legacy `public_key_pem` / `private_key_pem` columns, kept for
//     backward compatibility with M1/M2 rows (added before M3).
//  2. The dedicated ML-DSA-65 columns added in M3 (`mldsa_public_key_pem`,
//     `mldsa_private_key_pem`, `mldsa_private_key_wrapped`,
//     `mldsa_private_key_wrap_key_id`). M5 writes here.
//
// Whitepaper 2.2.2 + 2.2.3: when a WrappingKeyProvider is supplied, the
// secret key is wrapped under AES-256-GCM and stored in
// `mldsa_private_key_wrapped` (BLOB), with the keyring id in
// `mldsa_private_key_wrap_key_id`. The plaintext `mldsa_private_key_pem`
// stays NULL on the wrapped row. The public key is always stored in
// plaintext (`mldsa_public_key_pem`) so reads do not need the keyring to
// resolve the device id. The legacy `public_key_pem` / `private_key_pem`
// columns are still populated for backward compat with M1/M2 row shapes
// (they hold the same prefixed material) — a future milestone can drop
// them once no row pre-dates M5.
import {
  DeviceIdentityStorageError,
  identityWrappingContext,
  invalidStoredIdentityError,
  normalizeIdentityKey,
  parseCreatedAtMs,
  validateStoredDeviceIdentity,
  type StoredDeviceIdentity,
} from "./device-identity-store.crypto.js";
export {
  DeviceIdentityStorageError,
  generateStoredDeviceIdentity,
  PRIMARY_DEVICE_IDENTITY_KEY,
  validateStoredDeviceIdentity,
} from "./device-identity-store.crypto.js";
export type { DeviceIdentity, StoredDeviceIdentity } from "./device-identity-store.crypto.js";
import fs from "node:fs";
import path from "node:path";
import type { Selectable } from "kysely";
import { pqcLog, PQC_EVENT } from "../logging/pqc-log.js";
import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  unwrapSecret,
  type WrappedSecret,
  WrappedSecretVersionError,
  type WrappingKeyProvider,
  wrapSecret,
} from "../security/secret-wrapping.js";
import { withOpenClawStateDatabaseReadOnly } from "../state/openclaw-state-db-readonly.js";
import type { DB as OpenClawStateKyselyDatabase } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";
import { runDeviceIdentityPopulationPreflight } from "./device-identity-store.population-preflight.js";
import type { DeviceIdentityPopulationPreflight } from "./device-identity-store.population-preflight.js";
import {
  inspectStoredIdentityPopulation,
  upgradeStoredIdentityPopulation,
} from "./device-identity-store.wrapping-upgrade.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "./kysely-sync.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  isMlDsa65PublicKey,
  isMlDsa65SecretKey,
  MLDSA65_PUBLIC_KEY_LENGTH,
  MLDSA65_SECRET_KEY_LENGTH,
  mlDsa65KeyPairMatches,
} from "./mldsa65-key-storage.js";

export type { DeviceIdentityPopulationPreflight } from "./device-identity-store.population-preflight.js";

export type DeviceIdentityStoreOptions = OpenClawStateDatabaseOptions & {
  identityKey?: string;
  /** Optional PQC wrap-key provider. When supplied, generated identities
   *  are wrapped at rest and unwrapped on read. M6 will plumb the
   *  default keyring (File / Env / OS keyring) through this. */
  wrappingKeyProvider?: WrappingKeyProvider;
};

type DeviceIdentityDatabase = Pick<OpenClawStateKyselyDatabase, "device_identities">;
type DeviceIdentityRow = Selectable<DeviceIdentityDatabase["device_identities"]>;

/** Failure to authenticate/decrypt is not proof that the identity may be replaced. */
class DeviceIdentityKeyAccessError extends DeviceIdentityStorageError {}

function identityKeyAccessError(
  identityKey: string,
  cause?: unknown,
): DeviceIdentityKeyAccessError {
  return new DeviceIdentityKeyAccessError(
    `Cannot authenticate or decrypt device identity "${identityKey}". Restore its wrapping key before attempting repair.`,
    { cause },
  );
}

/** Convert a row to the internal `StoredDeviceIdentity` shape, unwrapping
 *  the wrapped form via the supplied keyring when present.
 *
 *  The keyring is read at the storage boundary, NOT in `validateStored…` —
 *  this keeps `validateStored…` deterministic and free of side effects on
 *  the keyring, while the read path is the single place that talks to it.
 *  If the wrapped form is present but the keyring is missing or the
 *  keyId is unknown, the row is treated as invalid (caller runs Doctor). */
function rowToStoredIdentity(
  row: DeviceIdentityRow,
  expectedIdentityKey: string,
  wrappingKeyProvider?: WrappingKeyProvider,
  allowLegacyWrapped = false,
): StoredDeviceIdentity {
  if (
    row.identity_key !== expectedIdentityKey ||
    typeof row.device_id !== "string" ||
    parseCreatedAtMs(row.created_at_ms) === null ||
    parseCreatedAtMs(row.updated_at_ms) === null
  ) {
    throw invalidStoredIdentityError(expectedIdentityKey);
  }

  // Read order for the public side: prefer the new `mldsa_public_key_pem`
  // (M3+) and fall back to the legacy `public_key_pem` (M1/M2 rows).
  // The fallback keeps the M5 migration non-destructive: existing rows
  // keep working until a Doctor backfill runs.
  const publicKeyPem =
    typeof row.mldsa_public_key_pem === "string" && row.mldsa_public_key_pem.length > 0
      ? row.mldsa_public_key_pem
      : typeof row.public_key_pem === "string"
        ? row.public_key_pem
        : null;

  // The wrap envelope (BLOB -> base64url string + keyId) is new in M3.
  // Legacy rows (M1/M2) have these columns as null and a plaintext secret
  // in `mldsa_private_key_pem` / `private_key_pem`.
  const wrappedBlob = row.mldsa_private_key_wrapped;
  const wrapKeyId = row.mldsa_private_key_wrap_key_id;
  const hasWrapped =
    wrappedBlob !== null &&
    wrappedBlob !== undefined &&
    wrappedBlob.length > 0 &&
    typeof wrapKeyId === "string" &&
    wrapKeyId.length > 0;

  // A partially populated wrapping envelope is corruption, not a legacy
  // plaintext row. Never fall back to a stale plaintext copy in that case.
  if ((wrappedBlob != null || wrapKeyId != null) && !hasWrapped) {
    throw invalidStoredIdentityError(expectedIdentityKey);
  }

  if (hasWrapped) {
    if (!wrappingKeyProvider) {
      // The row is wrapped but the caller didn't bring a keyring.
      // Refuse to silently fall back to plaintext: the operator must
      // configure the keyring or run Doctor, not have the runtime sign
      // with whatever it can find.
      throw new DeviceIdentityKeyAccessError(
        `device identity "${expectedIdentityKey}" is wrap-protected but no wrappingKeyProvider was supplied to the store`,
      );
    }
    const serialized = Buffer.from(wrappedBlob).toString("utf8");
    let wrapped: WrappedSecret;
    try {
      wrapped = deserializeWrappedSecret(serialized);
    } catch (error) {
      if (error instanceof WrappedSecretVersionError) {
        throw identityKeyAccessError(expectedIdentityKey, error);
      }
      throw invalidStoredIdentityError(expectedIdentityKey, error);
    }
    if (wrapped.keyId !== wrapKeyId) {
      throw identityKeyAccessError(
        expectedIdentityKey,
        new Error("wrapped device identity key id does not match its database metadata"),
      );
    }
    if (wrapped.version !== 2 && !allowLegacyWrapped) {
      throw new DeviceIdentityStorageError(
        `Device identity "${expectedIdentityKey}" needs an authenticated wrapping upgrade. Run "openclaw doctor --fix" before using it.`,
      );
    }
    let rawSecret: Buffer;
    try {
      rawSecret = unwrapSecret(
        wrapped,
        wrappingKeyProvider,
        wrapped.version === 2
          ? identityWrappingContext(expectedIdentityKey, row.device_id, publicKeyPem ?? "")
          : undefined,
      );
    } catch (error) {
      pqcLog.error(PQC_EVENT.DeviceIdentity, {
        status: "fail",
        identityKey: expectedIdentityKey,
        keyId: wrapKeyId,
        detail: "unwrap failed for stored identity",
      });
      throw identityKeyAccessError(expectedIdentityKey, error);
    }
    pqcLog.info(PQC_EVENT.DeviceIdentity, {
      status: "ok",
      identityKey: expectedIdentityKey,
      keyId: wrapKeyId,
      detail: "unwrapped stored identity",
    });
    try {
      if (rawSecret.length !== MLDSA65_SECRET_KEY_LENGTH) {
        throw invalidStoredIdentityError(
          expectedIdentityKey,
          new Error(
            `unwrapped secret key length ${rawSecret.length} != ${MLDSA65_SECRET_KEY_LENGTH}`,
          ),
        );
      }
      const privateKeyPem = encodeMlDsa65SecretKey(rawSecret);
      return {
        deviceId: row.device_id,
        publicKeyPem: publicKeyPem ?? "",
        privateKeyPem,
        createdAtMs: row.created_at_ms,
        mldsaPrivateKeyPem: null,
        mldsaPrivateKeyWrapped: serialized,
        mldsaPrivateKeyWrapKeyId: wrapKeyId,
      };
    } finally {
      rawSecret.fill(0);
    }
  }

  // Plaintext path: prefer the new `mldsa_private_key_pem` (M3+) and fall
  // back to the legacy `private_key_pem` (M1/M2 rows).
  const mldsaPrivateKeyPem =
    typeof row.mldsa_private_key_pem === "string" && row.mldsa_private_key_pem.length > 0
      ? row.mldsa_private_key_pem
      : null;
  const legacyPrivateKeyPem = typeof row.private_key_pem === "string" ? row.private_key_pem : null;
  const privateKeyPem = mldsaPrivateKeyPem ?? legacyPrivateKeyPem ?? "";

  return {
    deviceId: row.device_id,
    publicKeyPem: publicKeyPem ?? "",
    privateKeyPem,
    createdAtMs: row.created_at_ms,
    mldsaPrivateKeyPem,
    mldsaPrivateKeyWrapped: null,
    mldsaPrivateKeyWrapKeyId: null,
  };
}

function salvageStoredIdentityRow(
  row: DeviceIdentityRow,
  expectedIdentityKey: string,
  repairedAtMs: number,
  wrappingKeyProvider?: WrappingKeyProvider,
): StoredDeviceIdentity | null {
  // The PQC fork only stores one algorithm class (ML-DSA-65). Salvage is
  // limited to repairing the device_id fingerprint and timestamp; raw key
  // bytes are kept byte-for-byte because rotating them would invalidate
  // pairing and stored auth. M5 preserves the wrap envelope: if the row
  // has `mldsa_private_key_wrapped`, salvage keeps it; the unwrap happens
  // on read in `rowToStoredIdentity` once a keyring is supplied.
  if (row.identity_key !== expectedIdentityKey) {
    return null;
  }

  const wrappedBlob = row.mldsa_private_key_wrapped;
  const wrapKeyId = row.mldsa_private_key_wrap_key_id;
  const hasWrapped =
    wrappedBlob !== null &&
    wrappedBlob !== undefined &&
    wrappedBlob.length > 0 &&
    typeof wrapKeyId === "string" &&
    wrapKeyId.length > 0;

  if (hasWrapped) {
    let wrapped: WrappedSecret;
    try {
      wrapped = deserializeWrappedSecret(Buffer.from(wrappedBlob).toString("utf8"));
    } catch (error) {
      if (error instanceof WrappedSecretVersionError) {
        throw identityKeyAccessError(expectedIdentityKey, error);
      }
      return null;
    }
    // Metadata repair preserves keys only after authenticated unwrap and the
    // same pairing proof used by runtime reads; lengths alone do not prove it.
    const publicKeyPem =
      typeof row.mldsa_public_key_pem === "string" && row.mldsa_public_key_pem.length > 0
        ? row.mldsa_public_key_pem
        : typeof row.public_key_pem === "string"
          ? row.public_key_pem
          : null;
    if (publicKeyPem === null || !isMlDsa65PublicKey(publicKeyPem)) {
      if (wrapped.version === 2) {
        throw identityKeyAccessError(expectedIdentityKey);
      }
      return null;
    }
    let publicKeyRaw: Uint8Array;
    try {
      publicKeyRaw = decodeMlDsa65PublicKey(publicKeyPem);
    } catch {
      if (wrapped.version === 2) {
        throw identityKeyAccessError(expectedIdentityKey);
      }
      return null;
    }
    if (publicKeyRaw.length !== MLDSA65_PUBLIC_KEY_LENGTH) {
      if (wrapped.version === 2) {
        throw identityKeyAccessError(expectedIdentityKey);
      }
      return null;
    }
    try {
      if (!wrappingKeyProvider) {
        throw identityKeyAccessError(expectedIdentityKey);
      }
      if (wrapped.keyId !== wrapKeyId) {
        throw identityKeyAccessError(expectedIdentityKey);
      }
      let secret: Buffer;
      try {
        secret = unwrapSecret(
          wrapped,
          wrappingKeyProvider,
          wrapped.version === 2
            ? identityWrappingContext(expectedIdentityKey, row.device_id, publicKeyPem)
            : undefined,
        );
      } catch (error) {
        throw identityKeyAccessError(expectedIdentityKey, error);
      }
      try {
        if (!mlDsa65KeyPairMatches(publicKeyRaw, secret)) {
          return null;
        }
        // Only Doctor may trust an old unbound row after proving its key pair.
        // New envelopes must authenticate their persisted context before repair.
        const deviceId = fingerprintMlDsa65PublicKey(publicKeyRaw);
        const upgraded =
          wrapped.version === 2
            ? wrapped
            : wrapSecret(
                secret,
                wrappingKeyProvider,
                identityWrappingContext(expectedIdentityKey, deviceId, publicKeyPem),
              );
        const createdAtMs =
          parseCreatedAtMs(row.created_at_ms) ??
          parseCreatedAtMs(row.updated_at_ms) ??
          repairedAtMs;
        return {
          deviceId,
          publicKeyPem,
          privateKeyPem: "",
          createdAtMs,
          mldsaPrivateKeyPem: null,
          mldsaPrivateKeyWrapped: serializeWrappedSecret(upgraded),
          mldsaPrivateKeyWrapKeyId: upgraded.keyId,
        };
      } finally {
        secret.fill(0);
      }
    } catch (error) {
      if (error instanceof DeviceIdentityKeyAccessError) {
        throw error;
      }
      return null;
    }
  }

  // Plaintext salvage path. Prefer the new column, fall back to the
  // legacy column so M1/M2 rows can still be repaired.
  if (typeof row.public_key_pem !== "string" || typeof row.private_key_pem !== "string") {
    return null;
  }
  if (!isMlDsa65PublicKey(row.public_key_pem) || !isMlDsa65SecretKey(row.private_key_pem)) {
    return null;
  }
  try {
    const publicKeyRaw = decodeMlDsa65PublicKey(row.public_key_pem);
    const privateKeyRaw = decodeMlDsa65SecretKey(row.private_key_pem);
    if (
      publicKeyRaw.length !== MLDSA65_PUBLIC_KEY_LENGTH ||
      privateKeyRaw.length !== MLDSA65_SECRET_KEY_LENGTH
    ) {
      return null;
    }
    const createdAtMs =
      parseCreatedAtMs(row.created_at_ms) ?? parseCreatedAtMs(row.updated_at_ms) ?? repairedAtMs;
    const salvaged: StoredDeviceIdentity = {
      deviceId: fingerprintMlDsa65PublicKey(publicKeyRaw),
      publicKeyPem: row.public_key_pem,
      privateKeyPem: row.private_key_pem,
      createdAtMs,
      mldsaPrivateKeyPem:
        typeof row.mldsa_private_key_pem === "string" && row.mldsa_private_key_pem.length > 0
          ? row.mldsa_private_key_pem
          : row.private_key_pem,
      mldsaPrivateKeyWrapped: null,
      mldsaPrivateKeyWrapKeyId: null,
    };
    validateStoredDeviceIdentity(salvaged, expectedIdentityKey);
    return salvaged;
  } catch {
    return null;
  }
}

function storedIdentityToRow(
  identityKey: string,
  stored: StoredDeviceIdentity,
  updatedAtMs = stored.createdAtMs,
): DeviceIdentityRow {
  // The legacy `public_key_pem` / `private_key_pem` columns are kept in
  // sync with the new `mldsa_*` columns so callers that still read the
  // old shape (M1/M2 code paths) keep working. The plaintext PEM is
  // duplicated in `private_key_pem` even for wrapped rows — Doctor / log
  // lines that do not have the keyring can still see "this is an
  // ML-DSA-65 row" without ever unwrapping. The actual secret bytes
  // are NOT duplicated: wrapped rows leave `mldsa_private_key_pem` and
  // `private_key_pem` blank for the secret side.
  const privateKeyPemForLegacyColumn =
    stored.mldsaPrivateKeyPem ?? (stored.mldsaPrivateKeyWrapped ? "" : stored.privateKeyPem);

  return {
    identity_key: identityKey,
    device_id: stored.deviceId,
    public_key_pem: stored.publicKeyPem,
    private_key_pem: privateKeyPemForLegacyColumn,
    created_at_ms: stored.createdAtMs,
    updated_at_ms: updatedAtMs,
    mldsa_public_key_pem: stored.publicKeyPem,
    mldsa_private_key_pem: stored.mldsaPrivateKeyPem,
    mldsa_private_key_wrapped: stored.mldsaPrivateKeyWrapped
      ? new TextEncoder().encode(stored.mldsaPrivateKeyWrapped)
      : null,
    mldsa_private_key_wrap_key_id: stored.mldsaPrivateKeyWrapKeyId,
  };
}

function readStoredIdentityRowFromDatabase(
  database: { db: Parameters<typeof getNodeSqliteKysely>[0] },
  identityKey: string,
): DeviceIdentityRow | null {
  const db = getNodeSqliteKysely<DeviceIdentityDatabase>(database.db);
  return (
    executeSqliteQueryTakeFirstSync(
      database.db,
      db.selectFrom("device_identities").selectAll().where("identity_key", "=", identityKey),
    ) ?? null
  );
}

function readStoredIdentityFromDatabase(
  database: { db: Parameters<typeof getNodeSqliteKysely>[0] },
  identityKey: string,
  wrappingKeyProvider?: WrappingKeyProvider,
): StoredDeviceIdentity | null {
  const row = readStoredIdentityRowFromDatabase(database, identityKey);
  return row ? rowToStoredIdentity(row, identityKey, wrappingKeyProvider) : null;
}

/** Resolve the concrete database and row identity used by process caches and diagnostics. */
export function resolveDeviceIdentityStore(options: DeviceIdentityStoreOptions = {}): {
  databasePath: string;
  identityKey: string;
} {
  return {
    databasePath: path.resolve(
      options.path ?? resolveOpenClawStateSqlitePath(options.env ?? process.env),
    ),
    identityKey: normalizeIdentityKey(options.identityKey),
  };
}

/** Doctor census: authenticate Node rows and report every upgrade, block, or native-proof requirement. */
export function listDeviceIdentityWrappingUpgrades(
  options: DeviceIdentityStoreOptions = {},
): string[] {
  return inspectStoredIdentityPopulation(
    options,
    rowToStoredIdentity,
    (error) => error instanceof DeviceIdentityKeyAccessError,
  )
    .report.filter((row) => row.status !== "verified")
    .map((row) => row.identityKey);
}

export function upgradeDeviceIdentityPopulationWrapped(
  options: DeviceIdentityStoreOptions = {},
  params: { createMissingPrimary?: boolean } = {},
) {
  return upgradeStoredIdentityPopulation(
    options,
    rowToStoredIdentity,
    (error) => error instanceof DeviceIdentityKeyAccessError,
    storedIdentityToRow,
    params,
  );
}

/** Read the entire identity table on a dedicated SQLite read-only connection. No repair or key write. */
export async function preflightDeviceIdentityPopulationReadOnly(
  options: Omit<DeviceIdentityStoreOptions, "identityKey"> = {},
): Promise<DeviceIdentityPopulationPreflight> {
  return runDeviceIdentityPopulationPreflight(
    options,
    rowToStoredIdentity,
    (error) => error instanceof DeviceIdentityKeyAccessError,
  );
}

/** Read through the writable shared-state lifecycle, validating any existing row. */
export function readStoredDeviceIdentity(
  options: DeviceIdentityStoreOptions = {},
): StoredDeviceIdentity | null {
  const resolved = resolveDeviceIdentityStore(options);
  const database = openOpenClawStateDatabase({
    env: options.env,
    path: resolved.databasePath,
  });
  const stored = readStoredIdentityFromDatabase(
    database,
    resolved.identityKey,
    options.wrappingKeyProvider,
  );
  if (stored) {
    validateStoredDeviceIdentity(stored, resolved.identityKey);
  }
  return stored;
}

/** Read without creating, repairing, chmodding, or joining the writer lifecycle. */
export function readStoredDeviceIdentityReadOnly(
  options: DeviceIdentityStoreOptions = {},
): StoredDeviceIdentity | null {
  const resolved = resolveDeviceIdentityStore(options);
  try {
    fs.lstatSync(resolved.databasePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
    return null;
  }
  return withOpenClawStateDatabaseReadOnly(
    (database) => {
      const stored = readStoredIdentityFromDatabase(
        database,
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (stored) {
        validateStoredDeviceIdentity(stored, resolved.identityKey);
      }
      return stored;
    },
    { env: options.env, path: resolved.databasePath },
  );
}

/** Insert a candidate only when the key is still absent, then return the authoritative row. */
export function insertStoredDeviceIdentityIfAbsent(
  candidate: StoredDeviceIdentity,
  options: DeviceIdentityStoreOptions = {},
): StoredDeviceIdentity {
  const resolved = resolveDeviceIdentityStore(options);
  validateStoredDeviceIdentity(candidate, resolved.identityKey);
  return runOpenClawStateWriteTransaction(
    ({ db }) => {
      const existing = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (existing) {
        validateStoredDeviceIdentity(existing, resolved.identityKey);
      } else {
        const kysely = getNodeSqliteKysely<DeviceIdentityDatabase>(db);
        executeSqliteQuerySync(
          db,
          kysely
            .insertInto("device_identities")
            .values(storedIdentityToRow(resolved.identityKey, candidate))
            .onConflict((conflict) => conflict.column("identity_key").doNothing()),
        );
      }
      const authoritative = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (!authoritative) {
        throw new DeviceIdentityStorageError(
          `SQLite device identity "${resolved.identityKey}" was not durable after insert.`,
        );
      }
      validateStoredDeviceIdentity(authoritative, resolved.identityKey);
      return authoritative;
    },
    { env: options.env, path: resolved.databasePath },
    { operationLabel: "device-identity.create" },
  );
}

/** Replace only an invalid authoritative row; preserve a valid concurrent winner. */
export function repairInvalidStoredDeviceIdentity(
  candidate: StoredDeviceIdentity,
  options: DeviceIdentityStoreOptions = {},
): { identity: StoredDeviceIdentity; repaired: boolean; rotated: boolean } {
  const resolved = resolveDeviceIdentityStore(options);
  validateStoredDeviceIdentity(candidate, resolved.identityKey);
  return runOpenClawStateWriteTransaction(
    ({ db }) => {
      let repaired = false;
      let rotated = false;
      let existingRow: DeviceIdentityRow | null = null;
      try {
        existingRow = readStoredIdentityRowFromDatabase({ db }, resolved.identityKey);
        const existing = existingRow
          ? rowToStoredIdentity(existingRow, resolved.identityKey, options.wrappingKeyProvider)
          : null;
        if (existing) {
          validateStoredDeviceIdentity(existing, resolved.identityKey);
          return { identity: existing, repaired, rotated };
        }
      } catch (error) {
        if (error instanceof DeviceIdentityKeyAccessError) {
          throw error;
        }
        if (!(error instanceof DeviceIdentityStorageError)) {
          throw error;
        }
      }
      if (existingRow) {
        const salvaged = salvageStoredIdentityRow(
          existingRow,
          resolved.identityKey,
          candidate.createdAtMs,
          options.wrappingKeyProvider,
        );
        if (salvaged) {
          executeSqliteQuerySync(
            db,
            getNodeSqliteKysely<DeviceIdentityDatabase>(db)
              .updateTable("device_identities")
              .set(storedIdentityToRow(resolved.identityKey, salvaged, candidate.createdAtMs))
              .where("identity_key", "=", resolved.identityKey),
          );
          const authoritative = readStoredIdentityFromDatabase(
            { db },
            resolved.identityKey,
            options.wrappingKeyProvider,
          );
          if (!authoritative) {
            throw new DeviceIdentityStorageError(
              `SQLite device identity "${resolved.identityKey}" was not durable after repair.`,
            );
          }
          validateStoredDeviceIdentity(authoritative, resolved.identityKey);
          return { identity: authoritative, repaired: true, rotated };
        }
        executeSqliteQuerySync(
          db,
          getNodeSqliteKysely<DeviceIdentityDatabase>(db)
            .deleteFrom("device_identities")
            .where("identity_key", "=", resolved.identityKey),
        );
      }

      // An absent row after an invalid-row detection still means identity continuity was lost.
      // Report the generated winner so Doctor always surfaces the required re-approval.
      repaired = true;
      rotated = true;

      executeSqliteQuerySync(
        db,
        getNodeSqliteKysely<DeviceIdentityDatabase>(db)
          .insertInto("device_identities")
          .values(storedIdentityToRow(resolved.identityKey, candidate))
          .onConflict((conflict) => conflict.column("identity_key").doNothing()),
      );
      const authoritative = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (!authoritative) {
        throw new DeviceIdentityStorageError(
          `SQLite device identity "${resolved.identityKey}" was not durable after repair.`,
        );
      }
      validateStoredDeviceIdentity(authoritative, resolved.identityKey);
      return { identity: authoritative, repaired, rotated };
    },
    { env: options.env, path: resolved.databasePath },
    { operationLabel: "device-identity.doctor-repair" },
  );
}

/** Canonicalize a valid ML-DSA identity into wrapped-only at-rest storage. */
export function ensureStoredDeviceIdentityWrapped(options: DeviceIdentityStoreOptions = {}): {
  identity: StoredDeviceIdentity;
  rewrapped: boolean;
} {
  const resolved = resolveDeviceIdentityStore(options);
  const wrappingKeyProvider = options.wrappingKeyProvider;
  if (!wrappingKeyProvider) {
    throw new DeviceIdentityStorageError(
      "A wrapping key provider is required to canonicalize a device identity.",
    );
  }
  return runOpenClawStateWriteTransaction(
    ({ db }) => {
      const row = readStoredIdentityRowFromDatabase({ db }, resolved.identityKey);
      if (!row) {
        throw new DeviceIdentityStorageError(
          `SQLite device identity "${resolved.identityKey}" does not exist.`,
        );
      }
      const existing = rowToStoredIdentity(row, resolved.identityKey, wrappingKeyProvider, true);
      validateStoredDeviceIdentity(existing, resolved.identityKey);
      const alreadyCanonical =
        existing.mldsaPrivateKeyWrapped !== null &&
        deserializeWrappedSecret(existing.mldsaPrivateKeyWrapped).version === 2 &&
        row.mldsa_private_key_wrapped !== null &&
        row.mldsa_private_key_wrapped !== undefined &&
        row.mldsa_private_key_wrapped.length > 0 &&
        typeof row.mldsa_private_key_wrap_key_id === "string" &&
        row.mldsa_private_key_wrap_key_id.length > 0 &&
        row.mldsa_private_key_pem === null &&
        row.private_key_pem === "" &&
        row.mldsa_public_key_pem === existing.publicKeyPem &&
        row.public_key_pem === existing.publicKeyPem;
      if (alreadyCanonical) {
        return { identity: existing, rewrapped: false };
      }

      let rawSecret: Uint8Array | undefined;
      try {
        rawSecret = decodeMlDsa65SecretKey(existing.privateKeyPem);
        const wrapped = wrapSecret(
          Buffer.from(rawSecret),
          wrappingKeyProvider,
          identityWrappingContext(resolved.identityKey, existing.deviceId, existing.publicKeyPem),
        );
        const canonical: StoredDeviceIdentity = {
          ...existing,
          mldsaPrivateKeyPem: null,
          mldsaPrivateKeyWrapped: serializeWrappedSecret(wrapped),
          mldsaPrivateKeyWrapKeyId: wrapped.keyId,
        };
        validateStoredDeviceIdentity(canonical, resolved.identityKey);
        executeSqliteQuerySync(
          db,
          getNodeSqliteKysely<DeviceIdentityDatabase>(db)
            .updateTable("device_identities")
            .set(storedIdentityToRow(resolved.identityKey, canonical, Date.now()))
            .where("identity_key", "=", resolved.identityKey),
        );
      } finally {
        rawSecret?.fill(0);
      }
      const authoritative = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        wrappingKeyProvider,
      );
      if (!authoritative) {
        throw new DeviceIdentityStorageError(
          `SQLite device identity "${resolved.identityKey}" was not durable after wrapping.`,
        );
      }
      validateStoredDeviceIdentity(authoritative, resolved.identityKey);
      return { identity: authoritative, rewrapped: true };
    },
    { env: options.env, path: resolved.databasePath },
    { operationLabel: "device-identity.doctor-wrap" },
  );
}
