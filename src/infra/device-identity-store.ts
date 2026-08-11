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
import fs from "node:fs";
import path from "node:path";
import type { Insertable, Selectable } from "kysely";
import { withOpenClawStateDatabaseReadOnly } from "../state/openclaw-state-db-readonly.js";
import type { DB as OpenClawStateKyselyDatabase } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";
import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  unwrapSecret,
  type WrappedSecret,
  type WrappingKeyProvider,
  wrapSecret,
} from "../security/secret-wrapping.js";
import { pqcLog, PQC_EVENT } from "../logging/pqc-log.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  generateMlDsa65KeyPair,
  isMlDsa65PublicKey,
  isMlDsa65SecretKey,
  MLDSA65_PUBLIC_KEY_LENGTH,
  MLDSA65_SECRET_KEY_LENGTH,
} from "./mldsa65-key-storage.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "./kysely-sync.js";

export const PRIMARY_DEVICE_IDENTITY_KEY = "primary";

export type DeviceIdentity = {
  deviceId: string;
  publicKeyPem: string;
  privateKeyPem: string;
};

/** The internal / pre-persistence shape of a device identity. It carries
 *  either a plaintext ML-DSA-65 secret key PEM (`mldsaPrivateKeyPem`) or
 *  a wrapped form (`mldsaPrivateKeyWrapped` + `mldsaPrivateKeyWrapKeyId`),
 *  never both. The public side is always present in plaintext.
 *  `DeviceIdentity` (the public, post-validation shape) is the
 *  `privateKeyPem` string callers sign with; the internal fields here
 *  exist so the storage layer can persist the wrap envelope without
 *  round-tripping through the runtime type. */
export type StoredDeviceIdentity = DeviceIdentity & {
  createdAtMs: number;
  /** MLDSA65-SECRET-KEY: prefixed base64url, or null when a wrapped form is set. */
  mldsaPrivateKeyPem: string | null;
  /** Serialized WrappedSecret (base64url JSON), or null when plaintext. */
  mldsaPrivateKeyWrapped: string | null;
  /** Keyring id that sealed `mldsaPrivateKeyWrapped`, or null. */
  mldsaPrivateKeyWrapKeyId: string | null;
};

export type DeviceIdentityStoreOptions = OpenClawStateDatabaseOptions & {
  identityKey?: string;
  /** Optional PQC wrap-key provider. When supplied, generated identities
   *  are wrapped at rest and unwrapped on read. M6 will plumb the
   *  default keyring (File / Env / OS keyring) through this. */
  wrappingKeyProvider?: WrappingKeyProvider;
};

type DeviceIdentityDatabase = Pick<OpenClawStateKyselyDatabase, "device_identities">;
type DeviceIdentityRow = Selectable<DeviceIdentityDatabase["device_identities"]>;
type DeviceIdentityInsert = Insertable<DeviceIdentityDatabase["device_identities"]>;

export class DeviceIdentityStorageError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeviceIdentityStorageError";
  }
}

/** Convert the internal `StoredDeviceIdentity` (with the wrap envelope
 *  intact) to the public `DeviceIdentity` shape that callers sign with.
 *  The runtime never sees the wrapped form — only the unwrapped secret PEM. */
function storedIdentityToRuntime(stored: StoredDeviceIdentity): DeviceIdentity {
  return {
    deviceId: stored.deviceId,
    publicKeyPem: stored.publicKeyPem,
    privateKeyPem: stored.privateKeyPem,
  };
}

function normalizeIdentityKey(key: string | undefined): string {
  const normalized = key ?? PRIMARY_DEVICE_IDENTITY_KEY;
  if (normalized.length === 0 || normalized !== normalized.trim()) {
    throw new DeviceIdentityStorageError(
      "Device identity key must be a non-empty string without surrounding whitespace.",
    );
  }
  if (normalized.length > 128) {
    throw new DeviceIdentityStorageError("Device identity key exceeds 128 characters.");
  }
  return normalized;
}

function invalidStoredIdentityError(
  identityKey: string,
  cause?: unknown,
): DeviceIdentityStorageError {
  return new DeviceIdentityStorageError(
    `SQLite contains an invalid persisted device identity "${identityKey}". Run "openclaw doctor --fix" before starting the gateway or connecting this client.`,
    cause === undefined ? undefined : { cause },
  );
}

function fingerprintPublicKey(publicKeyPem: string): string {
  const raw = decodeMlDsa65PublicKey(publicKeyPem);
  return fingerprintMlDsa65PublicKey(raw);
}

/** Build the canonical `StoredDeviceIdentity` from a freshly generated
 *  ML-DSA-65 keypair. If a `wrappingKeyProvider` is supplied, the secret
 *  key is wrapped under AES-256-GCM and the plaintext PEM is set to null.
 *  The public side is always plaintext so the row's `device_id` is
 *  resolvable without the keyring.
 *
 *  This function is intentionally side-effect-free — it does NOT touch the
 *  database. The caller (the write transaction below) owns the persistence
 *  boundary. The optional `now` parameter keeps tests deterministic. */
export function generateStoredDeviceIdentity(
  now: number = Date.now(),
  wrappingKeyProvider?: WrappingKeyProvider,
): StoredDeviceIdentity {
  const { publicKey, secretKey } = generateMlDsa65KeyPair();
  const deviceId = fingerprintMlDsa65PublicKey(publicKey);
  const publicKeyPem = encodeMlDsa65PublicKey(publicKey);
  if (wrappingKeyProvider) {
    // Wrap the raw secret bytes (not the prefixed PEM) so the wrap
    // envelope is independent of the wire format. M5 stores the result
    // as a base64url JSON BLOB in `mldsa_private_key_wrapped`.
    const wrapped = wrapSecret(Buffer.from(secretKey), wrappingKeyProvider);
    pqcLog.info(PQC_EVENT.DeviceIdentity, {
      status: "ok",
      detail: "generated wrapped identity",
      keyId: wrapped.keyId,
    });
    return {
      deviceId,
      publicKeyPem,
      privateKeyPem: "", // populated lazily by `rowToStoredIdentity` on read
      createdAtMs: now,
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: serializeWrappedSecret(wrapped),
      mldsaPrivateKeyWrapKeyId: wrapped.keyId,
    };
  }
  const privateKeyPem = encodeMlDsa65SecretKey(secretKey);
  pqcLog.warn(PQC_EVENT.DeviceIdentity, {
    status: "ok",
    detail: "generated plaintext identity (no keyring)",
  });
  return {
    deviceId,
    publicKeyPem,
    privateKeyPem,
    createdAtMs: now,
    mldsaPrivateKeyPem: privateKeyPem,
    mldsaPrivateKeyWrapped: null,
    mldsaPrivateKeyWrapKeyId: null,
  };
}

function keyPairMatches(publicKeyPem: string, privateKeyPem: string): boolean {
  try {
    if (!isMlDsa65PublicKey(publicKeyPem) || !isMlDsa65SecretKey(privateKeyPem)) {
      return false;
    }
    const publicKeyRaw = decodeMlDsa65PublicKey(publicKeyPem);
    const privateKeyRaw = decodeMlDsa65SecretKey(privateKeyPem);
    return (
      publicKeyRaw.length === MLDSA65_PUBLIC_KEY_LENGTH &&
      privateKeyRaw.length === MLDSA65_SECRET_KEY_LENGTH
    );
  } catch {
    return false;
  }
}

function parseCreatedAtMs(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** Validate persisted key material and return the canonical runtime shape. */
export function validateStoredDeviceIdentity(
  value: StoredDeviceIdentity,
  identityKey = PRIMARY_DEVICE_IDENTITY_KEY,
): DeviceIdentity {
  try {
    if (
      !value.deviceId ||
      !/^[a-f0-9]{64}$/.test(value.deviceId) ||
      !value.publicKeyPem ||
      parseCreatedAtMs(value.createdAtMs) === null
    ) {
      throw invalidStoredIdentityError(identityKey);
    }
    // The plaintext form requires `privateKeyPem` to be a valid ML-DSA-65
    // PEM AND `mldsaPrivateKeyPem` to be a matching plaintext. The wrapped
    // form requires the wrap envelope to be parseable; the actual unwrap
    // is performed by `rowToStoredIdentity` because only the call site
    // holds the keyring. We do not unwrap here.
    const hasPlaintext = typeof value.privateKeyPem === "string"
      && value.privateKeyPem.length > 0
      && (value.mldsaPrivateKeyPem === null || value.mldsaPrivateKeyPem === value.privateKeyPem);
    const hasWrapped = typeof value.mldsaPrivateKeyWrapped === "string"
      && value.mldsaPrivateKeyWrapped.length > 0
      && typeof value.mldsaPrivateKeyWrapKeyId === "string"
      && value.mldsaPrivateKeyWrapKeyId.length > 0;
    if (!hasPlaintext && !hasWrapped) {
      throw invalidStoredIdentityError(identityKey);
    }
    if (hasPlaintext && !keyPairMatches(value.publicKeyPem, value.privateKeyPem)) {
      throw invalidStoredIdentityError(identityKey);
    }
    const derivedDeviceId = fingerprintPublicKey(value.publicKeyPem);
    if (derivedDeviceId !== value.deviceId) {
      throw invalidStoredIdentityError(identityKey);
    }
    return storedIdentityToRuntime(value);
  } catch (error) {
    if (error instanceof DeviceIdentityStorageError) {
      throw error;
    }
    throw invalidStoredIdentityError(identityKey, error);
  }
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
    (typeof row.mldsa_public_key_pem === "string" && row.mldsa_public_key_pem.length > 0
      ? row.mldsa_public_key_pem
      : typeof row.public_key_pem === "string"
        ? row.public_key_pem
        : null);

  // The wrap envelope (BLOB -> base64url string + keyId) is new in M3.
  // Legacy rows (M1/M2) have these columns as null and a plaintext secret
  // in `mldsa_private_key_pem` / `private_key_pem`.
  const wrappedBlob = row.mldsa_private_key_wrapped;
  const wrapKeyId = row.mldsa_private_key_wrap_key_id;
  const hasWrapped = wrappedBlob !== null
    && wrappedBlob !== undefined
    && wrappedBlob.length > 0
    && typeof wrapKeyId === "string"
    && wrapKeyId.length > 0;

  if (hasWrapped) {
    if (!wrappingKeyProvider) {
      // The row is wrapped but the caller didn't bring a keyring.
      // Refuse to silently fall back to plaintext: the operator must
      // configure the keyring or run Doctor, not have the runtime sign
      // with whatever it can find.
      throw new DeviceIdentityStorageError(
        `device identity "${expectedIdentityKey}" is wrap-protected but no wrappingKeyProvider was supplied to the store`,
      );
    }
    const serialized = Buffer.from(wrappedBlob).toString("utf8");
    let wrapped: WrappedSecret;
    try {
      wrapped = deserializeWrappedSecret(serialized);
    } catch (error) {
      throw invalidStoredIdentityError(expectedIdentityKey, error);
    }
    let rawSecret: Buffer;
    try {
      rawSecret = unwrapSecret(wrapped, wrappingKeyProvider);
    } catch (error) {
      pqcLog.error(PQC_EVENT.DeviceIdentity, {
        status: "fail",
        identityKey: expectedIdentityKey,
        keyId: wrapKeyId,
        detail: "unwrap failed for stored identity",
      });
      throw invalidStoredIdentityError(expectedIdentityKey, error);
    }
    pqcLog.info(PQC_EVENT.DeviceIdentity, {
      status: "ok",
      identityKey: expectedIdentityKey,
      keyId: wrapKeyId,
      detail: "unwrapped stored identity",
    });
    if (rawSecret.length !== MLDSA65_SECRET_KEY_LENGTH) {
      throw invalidStoredIdentityError(
        expectedIdentityKey,
        new Error(
          `unwrapped secret key length ${rawSecret.length} != ${MLDSA65_SECRET_KEY_LENGTH}`,
        ),
      );
    }
    const privateKeyPem = encodeMlDsa65SecretKey(new Uint8Array(rawSecret));
    return {
      deviceId: row.device_id,
      publicKeyPem: publicKeyPem ?? "",
      privateKeyPem,
      createdAtMs: row.created_at_ms,
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: serialized,
      mldsaPrivateKeyWrapKeyId: wrapKeyId,
    };
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
  const hasWrapped = wrappedBlob !== null
    && wrappedBlob !== undefined
    && wrappedBlob.length > 0
    && typeof wrapKeyId === "string"
    && wrapKeyId.length > 0;

  if (hasWrapped) {
    // Salvage is a same-row re-validation: we just need the public side
    // and a parseable wrap envelope. The private key is not required at
    // salvage time because Doctor runs without the keyring and only
    // fixes timestamps / device_id, not signing material.
    const publicKeyPem =
      (typeof row.mldsa_public_key_pem === "string" && row.mldsa_public_key_pem.length > 0
        ? row.mldsa_public_key_pem
        : typeof row.public_key_pem === "string"
          ? row.public_key_pem
          : null);
    if (publicKeyPem === null || !isMlDsa65PublicKey(publicKeyPem)) {
      return null;
    }
    let publicKeyRaw: Uint8Array;
    try {
      publicKeyRaw = decodeMlDsa65PublicKey(publicKeyPem);
    } catch {
      return null;
    }
    if (publicKeyRaw.length !== MLDSA65_PUBLIC_KEY_LENGTH) {
      return null;
    }
    const createdAtMs =
      parseCreatedAtMs(row.created_at_ms) ?? parseCreatedAtMs(row.updated_at_ms) ?? repairedAtMs;
    const salvaged: StoredDeviceIdentity = {
      deviceId: fingerprintMlDsa65PublicKey(publicKeyRaw),
      publicKeyPem,
      privateKeyPem: "", // unwrap happens on read; Doctor does not need the plaintext
      createdAtMs,
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: Buffer.from(wrappedBlob).toString("utf8"),
      mldsaPrivateKeyWrapKeyId: wrapKeyId,
    };
    // Validation is permissive here: we don't have the plaintext, so we
    // accept the wrap envelope and let the runtime unwrap later. Doctor
    // does not sign.
    return salvaged;
  }

  // Plaintext salvage path. Prefer the new column, fall back to the
  // legacy column so M1/M2 rows can still be repaired.
  if (
    typeof row.public_key_pem !== "string" ||
    typeof row.private_key_pem !== "string"
  ) {
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
): DeviceIdentityInsert {
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
        if (!(error instanceof DeviceIdentityStorageError)) {
          throw error;
        }
      }
      if (existingRow) {
        const salvaged = salvageStoredIdentityRow(
          existingRow,
          resolved.identityKey,
          candidate.createdAtMs,
        );
        if (salvaged) {
          executeSqliteQuerySync(
            db,
            getNodeSqliteKysely<DeviceIdentityDatabase>(db)
              .updateTable("device_identities")
              .set({
                device_id: salvaged.deviceId,
                public_key_pem: salvaged.publicKeyPem,
                private_key_pem: salvaged.privateKeyPem,
                created_at_ms: salvaged.createdAtMs,
                updated_at_ms: candidate.createdAtMs,
                mldsa_public_key_pem: salvaged.publicKeyPem,
                mldsa_private_key_pem: salvaged.mldsaPrivateKeyPem,
                mldsa_private_key_wrapped: salvaged.mldsaPrivateKeyWrapped
                  ? new TextEncoder().encode(salvaged.mldsaPrivateKeyWrapped)
                  : null,
                mldsa_private_key_wrap_key_id: salvaged.mldsaPrivateKeyWrapKeyId,
              })
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
