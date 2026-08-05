// Canonical SQLite storage for gateway/device Ed25519 identities.
import crypto from "node:crypto";
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
  wrapSecret,
  unwrapSecret,
  serializeWrappedSecret,
  deserializeWrappedSecret,
  type WrappingKeyProvider,
} from "../security/secret-wrapping.js";
import {
  deriveCanonicalEd25519PrivateKeyRaw,
  deriveCanonicalEd25519PublicKeyRaw,
} from "./ed25519-signature.js";
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
  /** NEW: ML-DSA-65 public key (PEM) for post-quantum signature */
  mldsaPublicKeyPem?: string;
  /** NEW: ML-DSA-65 private key (PEM) for post-quantum signature */
  mldsaPrivateKeyPem?: string;
};

export type StoredDeviceIdentity = DeviceIdentity & {
  createdAtMs: number;
};

export type DeviceIdentityStoreOptions = OpenClawStateDatabaseOptions & {
  identityKey?: string;
  /** PQC: when provided, private keys are wrapped with AES-256-GCM before
   *  being persisted and unwrapped on read. Legacy plaintext columns are
   *  also written/kept for backward compatibility. */
  wrappingProvider?: WrappingKeyProvider;
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
  const raw = deriveCanonicalEd25519PublicKeyRaw(publicKeyPem);
  return crypto.createHash("sha256").update(raw).digest("hex");
}

/** Generate canonical Ed25519 material before entering a synchronous write transaction. */
export function generateStoredDeviceIdentity(now = Date.now()): StoredDeviceIdentity {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  // NEW: ML-DSA-65 generation
  const { publicKey: mldsaPub, privateKey: mldsaPriv } = crypto.generateKeyPairSync("ml-dsa-65", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    deviceId: fingerprintPublicKey(publicKeyPem),
    publicKeyPem,
    privateKeyPem,
    mldsaPublicKeyPem: mldsaPub,
    mldsaPrivateKeyPem: mldsaPriv,
    createdAtMs: now,
  };
}

function keyPairMatches(publicKeyPem: string, privateKeyPem: string): boolean {
  try {
    deriveCanonicalEd25519PublicKeyRaw(publicKeyPem);
    deriveCanonicalEd25519PrivateKeyRaw(privateKeyPem);
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    if (publicKey.asymmetricKeyType !== "ed25519" || privateKey.asymmetricKeyType !== "ed25519") {
      return false;
    }
    const derivedPublicKey = crypto
      .createPublicKey(privateKeyPem)
      .export({ type: "spki", format: "der" });
    const storedPublicKey = publicKey.export({ type: "spki", format: "der" });
    return Buffer.from(derivedPublicKey).equals(Buffer.from(storedPublicKey));
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
      !value.privateKeyPem ||
      (value.mldsaPublicKeyPem && !value.mldsaPrivateKeyPem) ||
      (!value.mldsaPublicKeyPem && value.mldsaPrivateKeyPem) ||
      parseCreatedAtMs(value.createdAtMs) === null ||
      !keyPairMatches(value.publicKeyPem, value.privateKeyPem)
    ) {
      throw invalidStoredIdentityError(identityKey);
    }
    const derivedDeviceId = fingerprintPublicKey(value.publicKeyPem);
    if (derivedDeviceId !== value.deviceId) {
      throw invalidStoredIdentityError(identityKey);
    }
    return {
      deviceId: value.deviceId,
      publicKeyPem: value.publicKeyPem,
      privateKeyPem: value.privateKeyPem,
    };
  } catch (error) {
    if (error instanceof DeviceIdentityStorageError) {
      throw error;
    }
    throw invalidStoredIdentityError(identityKey, error);
  }
}

function rowToStoredIdentity(
  row: DeviceIdentityRow,
  expectedIdentityKey: string,
  wrappingProvider?: WrappingKeyProvider,
): StoredDeviceIdentity {
  if (
    row.identity_key !== expectedIdentityKey ||
    typeof row.device_id !== "string" ||
    typeof row.public_key_pem !== "string" ||
    parseCreatedAtMs(row.created_at_ms) === null ||
    parseCreatedAtMs(row.updated_at_ms) === null
  ) {
    throw invalidStoredIdentityError(expectedIdentityKey);
  }
  const privateKeyPem = unwrapPrivateKeyPem(
    row.private_key_pem,
    row.private_key_wrapped,
    row.private_key_wrap_key_id,
    wrappingProvider,
    expectedIdentityKey,
  );
  const mldsaPrivateKeyPem = unwrapPrivateKeyPem(
    row.mldsa_private_key_pem,
    row.mldsa_private_key_wrapped,
    row.mldsa_private_key_wrap_key_id,
    wrappingProvider,
    expectedIdentityKey,
  );
  return {
    deviceId: row.device_id,
    publicKeyPem: row.public_key_pem,
    privateKeyPem,
    mldsaPublicKeyPem: row.mldsa_public_key_pem ?? undefined,
    mldsaPrivateKeyPem,
    createdAtMs: row.created_at_ms,
  };
}

function unwrapPrivateKeyPem(
  legacyPem: unknown,
  wrapped: unknown,
  wrapKeyId: unknown,
  provider: WrappingKeyProvider | undefined,
  identityKey: string,
): string | undefined {
  if (
    provider &&
    typeof legacyPem === "string" &&
    typeof wrapped === "string" &&
    typeof wrapKeyId === "string"
  ) {
    return unwrapSecret(deserializeWrappedSecret(wrapped), provider).toString("utf8");
  }
  if (typeof legacyPem === "string") {
    return legacyPem;
  }
  // PQC: nullable columns (e.g. mldsa_private_key_pem on legacy rows that
  // predate 2.1) are not an error - preserve the 2.1 behavior of `?? undefined`.
  if (legacyPem === null || legacyPem === undefined) {
    return undefined;
  }
  throw invalidStoredIdentityError(identityKey);
}

function salvageStoredIdentityRow(
  row: DeviceIdentityRow,
  expectedIdentityKey: string,
  repairedAtMs: number,
): StoredDeviceIdentity | null {
  // Device ids, timestamps, and PEM framing are repairable metadata. Preserve matching
  // Ed25519 key bytes because rotating them would invalidate pairing and stored auth.
  if (
    row.identity_key !== expectedIdentityKey ||
    typeof row.public_key_pem !== "string" ||
    typeof row.private_key_pem !== "string"
  ) {
    return null;
  }
  try {
    const publicKey = crypto.createPublicKey(row.public_key_pem);
    const privateKey = crypto.createPrivateKey(row.private_key_pem);
    if (publicKey.asymmetricKeyType !== "ed25519" || privateKey.asymmetricKeyType !== "ed25519") {
      return null;
    }
    const canonicalPublicKeyPem = publicKey.export({ type: "spki", format: "pem" });
    const canonicalPrivateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
    const derivedPublicKeyPem = crypto
      .createPublicKey(canonicalPrivateKeyPem)
      .export({ type: "spki", format: "pem" });
    if (derivedPublicKeyPem !== canonicalPublicKeyPem) {
      return null;
    }
    const createdAtMs =
      parseCreatedAtMs(row.created_at_ms) ?? parseCreatedAtMs(row.updated_at_ms) ?? repairedAtMs;
    const salvaged = {
      deviceId: fingerprintPublicKey(canonicalPublicKeyPem),
      publicKeyPem: canonicalPublicKeyPem,
      privateKeyPem: canonicalPrivateKeyPem,
      createdAtMs,
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
  wrappingProvider?: WrappingKeyProvider,
): DeviceIdentityInsert {
  const row: DeviceIdentityInsert = {
    identity_key: identityKey,
    device_id: stored.deviceId,
    public_key_pem: stored.publicKeyPem,
    private_key_pem: stored.privateKeyPem,
    mldsa_public_key_pem: stored.mldsaPublicKeyPem,
    mldsa_private_key_pem: stored.mldsaPrivateKeyPem,
    created_at_ms: stored.createdAtMs,
    updated_at_ms: updatedAtMs,
  };
  if (wrappingProvider) {
    if (stored.privateKeyPem) {
      const wrapped = wrapSecret(Buffer.from(stored.privateKeyPem, "utf8"), wrappingProvider);
      row.private_key_wrapped = serializeWrappedSecret(wrapped);
      row.private_key_wrap_key_id = wrapped.keyId;
    }
    if (stored.mldsaPrivateKeyPem) {
      const wrapped = wrapSecret(Buffer.from(stored.mldsaPrivateKeyPem, "utf8"), wrappingProvider);
      row.mldsa_private_key_wrapped = serializeWrappedSecret(wrapped);
      row.mldsa_private_key_wrap_key_id = wrapped.keyId;
    }
  }
  return row;
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
  wrappingProvider?: WrappingKeyProvider,
): StoredDeviceIdentity | null {
  const row = readStoredIdentityRowFromDatabase(database, identityKey);
  return row ? rowToStoredIdentity(row, identityKey, wrappingProvider) : null;
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
    options.wrappingProvider,
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
        options.wrappingProvider,
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
        options.wrappingProvider,
      );
      if (existing) {
        validateStoredDeviceIdentity(existing, resolved.identityKey);
      } else {
        const kysely = getNodeSqliteKysely<DeviceIdentityDatabase>(db);
        executeSqliteQuerySync(
          db,
          kysely
            .insertInto("device_identities")
            .values(
              storedIdentityToRow(
                resolved.identityKey,
                candidate,
                undefined,
                options.wrappingProvider,
              ),
            )
            .onConflict((conflict) => conflict.column("identity_key").doNothing()),
        );
      }
      const authoritative = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingProvider,
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
          ? rowToStoredIdentity(existingRow, resolved.identityKey, options.wrappingProvider)
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
          const repairSet: Parameters<ReturnType<typeof getNodeSqliteKysely<DeviceIdentityDatabase>>["updateTable"]>[1] = {
            device_id: salvaged.deviceId,
            public_key_pem: salvaged.publicKeyPem,
            private_key_pem: salvaged.privateKeyPem,
            created_at_ms: salvaged.createdAtMs,
            updated_at_ms: candidate.createdAtMs,
          };
          if (options.wrappingProvider) {
            const salvagedWrapped = wrapSecret(
              Buffer.from(salvaged.privateKeyPem, "utf8"),
              options.wrappingProvider,
            );
            repairSet.private_key_wrapped = serializeWrappedSecret(salvagedWrapped);
            repairSet.private_key_wrap_key_id = salvagedWrapped.keyId;
          }
          executeSqliteQuerySync(
            db,
            getNodeSqliteKysely<DeviceIdentityDatabase>(db)
              .updateTable("device_identities")
              .set(repairSet)
              .where("identity_key", "=", resolved.identityKey),
          );
          const authoritative = readStoredIdentityFromDatabase(
            { db },
            resolved.identityKey,
            options.wrappingProvider,
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
          .values(
            storedIdentityToRow(
              resolved.identityKey,
              candidate,
              undefined,
              options.wrappingProvider,
            ),
          )
          .onConflict((conflict) => conflict.column("identity_key").doNothing()),
      );
      const authoritative = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingProvider,
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
