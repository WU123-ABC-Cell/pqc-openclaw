// Identity construction, validation and authenticated wrapping context.
// SQLite reads and Doctor persistence remain in device-identity-store.ts.
import { pqcLog, PQC_EVENT } from "../logging/pqc-log.js";
import {
  serializeWrappedSecret,
  wrapSecret,
  type WrappingKeyProvider,
} from "../security/secret-wrapping.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  generateMlDsa65KeyPair,
  isMlDsa65PublicKey,
  isMlDsa65SecretKey,
  mlDsa65KeyPairMatches,
} from "./mldsa65-key-storage.js";

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

export function normalizeIdentityKey(key: string | undefined): string {
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

export function invalidStoredIdentityError(
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

export function identityWrappingContext(
  identityKey: string,
  deviceId: string,
  publicKeyPem: string,
): Buffer {
  const canonicalPublicKey = encodeMlDsa65PublicKey(decodeMlDsa65PublicKey(publicKeyPem));
  return Buffer.from(
    JSON.stringify(["device_identities", identityKey, deviceId, canonicalPublicKey]),
  );
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
  options: { allowPlaintextPrivateKey?: boolean; identityKey?: string } = {},
): StoredDeviceIdentity {
  if (!wrappingKeyProvider && options.allowPlaintextPrivateKey !== true) {
    throw new DeviceIdentityStorageError(
      "Refusing to generate a plaintext device identity without a wrapping key provider.",
    );
  }
  const { publicKey, secretKey } = generateMlDsa65KeyPair();
  const deviceId = fingerprintMlDsa65PublicKey(publicKey);
  const publicKeyPem = encodeMlDsa65PublicKey(publicKey);
  if (wrappingKeyProvider) {
    // Wrap the raw secret bytes (not the prefixed PEM) so the wrap
    // envelope is independent of the wire format. M5 stores the result
    // as a base64url JSON BLOB in `mldsa_private_key_wrapped`.
    const wrapped = wrapSecret(
      Buffer.from(secretKey),
      wrappingKeyProvider,
      identityWrappingContext(normalizeIdentityKey(options.identityKey), deviceId, publicKeyPem),
    );
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
  let privateKeyRaw: Uint8Array | undefined;
  try {
    if (!isMlDsa65PublicKey(publicKeyPem) || !isMlDsa65SecretKey(privateKeyPem)) {
      return false;
    }
    const publicKeyRaw = decodeMlDsa65PublicKey(publicKeyPem);
    privateKeyRaw = decodeMlDsa65SecretKey(privateKeyPem);
    return mlDsa65KeyPairMatches(publicKeyRaw, privateKeyRaw);
  } catch {
    return false;
  } finally {
    privateKeyRaw?.fill(0);
  }
}

export function parseCreatedAtMs(value: unknown): number | null {
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
    const hasPlaintext =
      typeof value.privateKeyPem === "string" &&
      value.privateKeyPem.length > 0 &&
      (value.mldsaPrivateKeyPem === null || value.mldsaPrivateKeyPem === value.privateKeyPem);
    const hasWrapped =
      typeof value.mldsaPrivateKeyWrapped === "string" &&
      value.mldsaPrivateKeyWrapped.length > 0 &&
      typeof value.mldsaPrivateKeyWrapKeyId === "string" &&
      value.mldsaPrivateKeyWrapKeyId.length > 0;
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
