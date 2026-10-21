import { createHash } from "node:crypto";
import type { Selectable } from "kysely";
import {
  deserializeWrappedSecret,
  type WrappingKeyProvider,
  WrappedSecretVersionError,
} from "../security/secret-wrapping.js";
import type { DB as OpenClawStateKyselyDatabase } from "../state/openclaw-state-db.generated.js";
import {
  openExistingOpenClawStateDatabaseReadOnly,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import {
  invalidStoredIdentityError,
  normalizeIdentityKey,
  parseCreatedAtMs,
  validateStoredDeviceIdentity,
  type StoredDeviceIdentity,
} from "./device-identity-store.crypto.js";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "./kysely-sync.js";

type DeviceIdentityPopulationRow = {
  identityKey: string;
  kind: "node-v2" | "node-v1" | "node-plaintext" | "apple-seed" | "unknown";
  status: "verified" | "needs-upgrade" | "needs-native-verification" | "blocked";
  reason?: "invalid-row" | "unsupported-envelope" | "key-unavailable";
  wrappingKeyId?: string;
};

export type DeviceIdentityPopulationPreflight = {
  databaseExists: boolean;
  rows: DeviceIdentityPopulationRow[];
  /** A row census, not authorization to migrate or rotate keys. */
  allRowsVerified: boolean;
};

type IdentityRow = Selectable<OpenClawStateKyselyDatabase["device_identities"]>;
type ReadRow = (
  row: IdentityRow,
  identityKey: string,
  provider?: WrappingKeyProvider,
  allowLegacyWrapped?: boolean,
) => StoredDeviceIdentity;

const APPLE_IDENTITY_KEYS = new Set([
  "apple-mldsa65-primary",
  "apple-mldsa65-node",
  "apple-mldsa65-shareExtension",
]);

function canonicalAppleKey(value: string, prefix: string, length: number): Buffer | null {
  if (typeof value !== "string" || !value.startsWith(prefix)) {
    return null;
  }
  const encoded = value.slice(prefix.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
    return null;
  }
  const raw = Buffer.from(encoded, "base64");
  return raw.length === length && raw.toString("base64") === encoded ? raw : null;
}

/** Classify one raw row; no private material or envelope bytes leave this function. */
export function inspectIdentityPopulationRow(
  row: IdentityRow,
  wrappingKeyProvider: WrappingKeyProvider | undefined,
  readRow: ReadRow,
  isKeyAccessError: (error: unknown) => boolean,
): DeviceIdentityPopulationRow {
  const identityKey = row.identity_key;
  const base = { identityKey };
  try {
    if (normalizeIdentityKey(identityKey) !== identityKey) {
      throw new Error("non-canonical identity key");
    }
  } catch {
    return { ...base, kind: "unknown", status: "blocked", reason: "invalid-row" };
  }
  if (APPLE_IDENTITY_KEYS.has(identityKey)) {
    const publicKey = canonicalAppleKey(row.public_key_pem, "MLDSA65-PUBLIC-KEY:", 1952);
    const seed = canonicalAppleKey(row.private_key_pem, "MLDSA65-SEED:", 32);
    const hasNodeColumns =
      row.mldsa_public_key_pem != null ||
      row.mldsa_private_key_pem != null ||
      row.mldsa_private_key_wrapped != null ||
      row.mldsa_private_key_wrap_key_id != null;
    const validMetadata =
      parseCreatedAtMs(row.created_at_ms) !== null &&
      parseCreatedAtMs(row.updated_at_ms) !== null &&
      publicKey !== null &&
      createHash("sha256").update(publicKey).digest("hex") === row.device_id;
    seed?.fill(0);
    publicKey?.fill(0);
    if (hasNodeColumns || seed === null || !validMetadata) {
      return { ...base, kind: "apple-seed", status: "blocked", reason: "invalid-row" };
    }
    // CryptoKit alone can prove the seed/public pair; Node must not certify it.
    return { ...base, kind: "apple-seed", status: "needs-native-verification" };
  }

  const wrapped = row.mldsa_private_key_wrapped;
  const hasEnvelope = wrapped != null || row.mldsa_private_key_wrap_key_id != null;
  let kind: DeviceIdentityPopulationRow["kind"] = hasEnvelope ? "unknown" : "node-plaintext";
  let wrappingKeyId: string | undefined;
  if (hasEnvelope) {
    try {
      if (!wrapped || !row.mldsa_private_key_wrap_key_id) {
        throw new Error("partial envelope");
      }
      const envelope = deserializeWrappedSecret(Buffer.from(wrapped).toString("utf8"));
      wrappingKeyId = row.mldsa_private_key_wrap_key_id;
      if (envelope.keyId !== wrappingKeyId) {
        throw new Error("key id mismatch");
      }
      kind = envelope.version === 2 ? "node-v2" : "node-v1";
    } catch (error) {
      return {
        ...base,
        kind,
        status: "blocked",
        reason: error instanceof WrappedSecretVersionError ? "unsupported-envelope" : "invalid-row",
      };
    }
    if (row.private_key_pem || row.mldsa_private_key_pem) {
      return { ...base, kind, status: "blocked", reason: "invalid-row", wrappingKeyId };
    }
  }
  try {
    const stored = readRow(row, identityKey, wrappingKeyProvider, kind === "node-v1");
    validateStoredDeviceIdentity(stored, identityKey);
    // Older six-column rows may omit dedicated copies; contradictory populated
    // copies are not authority to silently choose one identity during upgrade.
    if (
      (row.public_key_pem && row.public_key_pem !== stored.publicKeyPem) ||
      (row.mldsa_public_key_pem && row.mldsa_public_key_pem !== stored.publicKeyPem) ||
      (kind === "node-plaintext" &&
        ((row.private_key_pem && row.private_key_pem !== stored.privateKeyPem) ||
          (row.mldsa_private_key_pem && row.mldsa_private_key_pem !== stored.privateKeyPem)))
    ) {
      throw invalidStoredIdentityError(identityKey);
    }
    if (
      kind === "node-v2" &&
      (row.mldsa_public_key_pem !== stored.publicKeyPem ||
        row.public_key_pem !== stored.publicKeyPem)
    ) {
      throw invalidStoredIdentityError(identityKey);
    }
    return {
      ...base,
      kind,
      status: kind === "node-v2" ? "verified" : "needs-upgrade",
      ...(wrappingKeyId ? { wrappingKeyId } : {}),
    };
  } catch (error) {
    return {
      ...base,
      kind,
      status: "blocked",
      reason: isKeyAccessError(error) ? "key-unavailable" : "invalid-row",
      ...(wrappingKeyId ? { wrappingKeyId } : {}),
    };
  }
}

/** One complete SELECT on a dedicated read-only connection; recheck before mutation. */
export async function runDeviceIdentityPopulationPreflight(
  options: OpenClawStateDatabaseOptions & { wrappingKeyProvider?: WrappingKeyProvider },
  readRow: ReadRow,
  isKeyAccessError: (error: unknown) => boolean,
): Promise<DeviceIdentityPopulationPreflight> {
  const database = await openExistingOpenClawStateDatabaseReadOnly(options);
  if (!database) {
    return { databaseExists: false, rows: [], allRowsVerified: false };
  }
  try {
    const { rows } = executeSqliteQuerySync(
      database.db,
      getNodeSqliteKysely<Pick<OpenClawStateKyselyDatabase, "device_identities">>(database.db)
        .selectFrom("device_identities")
        .selectAll()
        .orderBy("identity_key"),
    );
    const inspected = rows.map((row) =>
      inspectIdentityPopulationRow(row, options.wrappingKeyProvider, readRow, isKeyAccessError),
    );
    return {
      databaseExists: true,
      rows: inspected,
      allRowsVerified: inspected.every((row) => row.status === "verified"),
    };
  } finally {
    database.walMaintenance.close();
  }
}
