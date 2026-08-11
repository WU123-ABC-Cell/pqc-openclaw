// Gateway/device ML-DSA-65 (FIPS 204) identity API backed by canonical shared
// SQLite state.
//
// PQC fork: every sign/verify/fingerprint call below uses ML-DSA-65 — there
// is no Ed25519 fallback by design (per the fork's PQC direction). The Ed25519
// helpers in ed25519-signature.ts are kept for the dual-sign transitional API
// only and are NOT exposed here.
//
// `DeviceIdentity.publicKeyPem` / `privateKeyPem` carry ML-DSA-65 material
// tagged with the MLDSA65-PUBLIC-KEY: / MLDSA65-SECRET-KEY: wire prefix (see
// mldsa65-key-storage.ts). They are stored verbatim in the corresponding
// SQLite TEXT columns and round-trip without conversion.
import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import { acquireDeviceIdentityCoordinator } from "./device-identity-coordinator.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  PRIMARY_DEVICE_IDENTITY_KEY,
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  resolveDeviceIdentityStore,
  type DeviceIdentity,
  type DeviceIdentityStoreOptions,
  type StoredDeviceIdentity,
} from "./device-identity-store.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  isMlDsa65PublicKey,
  isMlDsa65SecretKey,
  signMlDsa65Payload as signMlDsa65PayloadRaw,
  verifyMlDsa65Signature as verifyMlDsa65SignatureRaw,
} from "./mldsa65-key-storage.js";
import { pruneMapToMaxSize } from "./map-size.js";

export type { DeviceIdentity } from "./device-identity-store.js";

const LEGACY_DEVICE_IDENTITY_RELATIVE_PATH = path.join("identity", "device.json");
const DOCTOR_CLAIM_SUFFIX = ".doctor-importing";
const NATIVE_CLAIM_SUFFIX = ".native-importing";

class DeviceIdentityMigrationRequiredError extends Error {
  constructor(filePath: string) {
    super(
      `Legacy device identity exists at ${filePath}. Run "openclaw doctor --fix" before starting the gateway or connecting this client.`,
    );
    this.name = "DeviceIdentityMigrationRequiredError";
  }
}

function toDeviceIdentity(stored: StoredDeviceIdentity): DeviceIdentity {
  return {
    deviceId: stored.deviceId,
    publicKeyPem: stored.publicKeyPem,
    privateKeyPem: stored.privateKeyPem,
  };
}

function pathMayExist(filePath: string): boolean {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

function resolveLegacyStateDir(options: DeviceIdentityStoreOptions): string {
  if (options.env?.OPENCLAW_STATE_DIR?.trim()) {
    return resolveStateDir(options.env);
  }
  if (options.path) {
    const databaseDir = path.dirname(path.resolve(options.path));
    return path.basename(databaseDir) === "state" ? path.dirname(databaseDir) : databaseDir;
  }
  return resolveStateDir(options.env ?? process.env);
}

/** Exact retired file owned by Doctor migration code. */
function resolveLegacyDeviceIdentityPath(options: DeviceIdentityStoreOptions = {}): string {
  return path.join(resolveLegacyStateDir(options), LEGACY_DEVICE_IDENTITY_RELATIVE_PATH);
}

function assertNoPendingLegacyIdentity(options: DeviceIdentityStoreOptions): void {
  const { identityKey } = resolveDeviceIdentityStore(options);
  if (identityKey !== PRIMARY_DEVICE_IDENTITY_KEY) {
    return;
  }
  const legacyPath = resolveLegacyDeviceIdentityPath(options);
  if (
    // Claims first, source last: both migration owners restore claim -> source atomically.
    pathMayExist(`${legacyPath}${DOCTOR_CLAIM_SUFFIX}`) ||
    pathMayExist(`${legacyPath}${NATIVE_CLAIM_SUFFIX}`) ||
    pathMayExist(legacyPath)
  ) {
    throw new DeviceIdentityMigrationRequiredError(legacyPath);
  }
}

function withDeviceIdentityCoordinator<T>(
  options: DeviceIdentityStoreOptions,
  operation: (
    resolved: ReturnType<typeof resolveDeviceIdentityStore>,
    resolvedOptions: DeviceIdentityStoreOptions,
  ) => T,
): T {
  const resolved = resolveDeviceIdentityStore(options);
  const resolvedOptions: DeviceIdentityStoreOptions = {
    ...options,
    path: resolved.databasePath,
    identityKey: resolved.identityKey,
  };
  const coordinator = acquireDeviceIdentityCoordinator({
    databasePath: resolved.databasePath,
    env: options.env,
  });
  let result: T;
  try {
    result = operation(resolved, resolvedOptions);
  } catch (operationError) {
    try {
      coordinator.release();
    } catch (releaseError) {
      const aggregateError = new AggregateError(
        [operationError, releaseError],
        "device identity operation and coordinator release both failed",
        { cause: releaseError },
      );
      throw aggregateError;
    }
    throw operationError;
  }
  coordinator.release();
  return result;
}

function loadOrCreateDeviceIdentityOwned(options: DeviceIdentityStoreOptions): DeviceIdentity {
  assertNoPendingLegacyIdentity(options);
  const existing = readStoredDeviceIdentity(options);
  if (existing) {
    return toDeviceIdentity(existing);
  }

  // Generate outside the write transaction. The transaction rereads the row
  // before inserting so concurrent runtimes converge on one authoritative key.
  const candidate = generateStoredDeviceIdentity();
  return toDeviceIdentity(insertStoredDeviceIdentityIfAbsent(candidate, options));
}

/** Load a valid canonical identity or atomically create its SQLite row. */
export function loadOrCreateDeviceIdentity(
  options: DeviceIdentityStoreOptions = {},
): DeviceIdentity {
  return withDeviceIdentityCoordinator(options, (_resolved, resolvedOptions) =>
    loadOrCreateDeviceIdentityOwned(resolvedOptions),
  );
}

const processDeviceIdentities = new Map<string, DeviceIdentity>();
const MAX_PROCESS_DEVICE_IDENTITIES = 32;

/** Keep one authoritative identity stable for the lifetime of a state-dir process. */
export function loadOrCreateProcessDeviceIdentity(
  options: DeviceIdentityStoreOptions = {},
): DeviceIdentity {
  return withDeviceIdentityCoordinator(options, (resolved, resolvedOptions) => {
    assertNoPendingLegacyIdentity(resolvedOptions);
    const cacheKey = `${resolved.databasePath}\0${resolved.identityKey}`;
    const cached = processDeviceIdentities.get(cacheKey);
    if (cached) {
      return cached;
    }
    const identity = loadOrCreateDeviceIdentityOwned(resolvedOptions);
    pruneMapToMaxSize(processDeviceIdentities, MAX_PROCESS_DEVICE_IDENTITIES - 1);
    processDeviceIdentities.set(cacheKey, identity);
    return identity;
  });
}

/** Load a valid persisted identity without creating or mutating SQLite state. */
export function loadDeviceIdentityIfPresent(
  options: DeviceIdentityStoreOptions = {},
): DeviceIdentity | null {
  return withDeviceIdentityCoordinator(options, (_resolved, resolvedOptions) => {
    assertNoPendingLegacyIdentity(resolvedOptions);
    const stored = readStoredDeviceIdentityReadOnly(resolvedOptions);
    return stored ? toDeviceIdentity(stored) : null;
  });
}

/** Sign a UTF-8 payload with an ML-DSA-65 secret key (the `MLDSA65-SECRET-KEY:`
 *  prefixed base64url string stored in `DeviceIdentity.privateKeyPem`).
 *  Returns a base64url-encoded 3309-byte FIPS 204 signature. */
export function signDevicePayload(privateKeyPem: string, payload: string): string {
  if (!isMlDsa65SecretKey(privateKeyPem)) {
    throw new Error(
      "Device identity private key is not in MLDSA65-SECRET-KEY: format; " +
        "this fork stores ML-DSA-65 only (no Ed25519 fallback).",
    );
  }
  const secretKey = decodeMlDsa65SecretKey(privateKeyPem);
  return signMlDsa65PayloadRaw(secretKey, payload);
}

/** Normalize the MLDSA65-PUBLIC-KEY: prefixed string to canonical raw 1952-byte
 *  public key, then base64url-encode it. Returns null on any decode failure. */
export function normalizeDevicePublicKeyBase64Url(publicKey: string): string | null {
  try {
    if (!isMlDsa65PublicKey(publicKey)) {
      return null;
    }
    const raw = decodeMlDsa65PublicKey(publicKey);
    return Buffer.from(raw).toString("base64url");
  } catch {
    return null;
  }
}

/** Derive the stable 64-hex-char device id (SHA-256 of the raw 1952-byte
 *  ML-DSA-65 public key) from an MLDSA65-PUBLIC-KEY: prefixed string. */
export function deriveDeviceIdFromPublicKey(publicKey: string): string | null {
  try {
    if (!isMlDsa65PublicKey(publicKey)) {
      return null;
    }
    const raw = decodeMlDsa65PublicKey(publicKey);
    return fingerprintMlDsa65PublicKey(raw);
  } catch {
    return null;
  }
}

/** Export an MLDSA65-PUBLIC-KEY: prefixed string's raw 1952-byte public key
 *  as canonical base64url bytes. Throws on any decode failure or non-ML-DSA-65
 *  input — the runtime path that loads `DeviceIdentity` already enforces the
 *  MLDSA65-PUBLIC-KEY: prefix, so this is the strict post-validity helper.
 *  For untrusted / wire-format input, use `tryDecodeMlDsa65PublicKeyRaw` below
 *  which returns null on failure. */
export function publicKeyRawBase64UrlFromPem(publicKeyPem: string): string {
  if (!isMlDsa65PublicKey(publicKeyPem)) {
    throw new Error(
      "publicKeyRawBase64UrlFromPem: input is not an MLDSA65-PUBLIC-KEY: prefixed string; " +
        "this fork stores ML-DSA-65 only (no Ed25519 fallback).",
    );
  }
  const raw = decodeMlDsa65PublicKey(publicKeyPem);
  return Buffer.from(raw).toString("base64url");
}

/** Defensive variant of `publicKeyRawBase64UrlFromPem` that returns null on
 *  any decode failure. Use for untrusted / wire-format input where the
 *  caller wants to inspect / fail-closed without throwing. */
export function tryDecodeMlDsa65PublicKeyRaw(publicKeyPem: string): string | null {
  try {
    if (!isMlDsa65PublicKey(publicKeyPem)) {
      return null;
    }
    const raw = decodeMlDsa65PublicKey(publicKeyPem);
    return Buffer.from(raw).toString("base64url");
  } catch {
    return null;
  }
}

/** Verify a base64url ML-DSA-65 signature against an MLDSA65-PUBLIC-KEY:
 *  prefixed public key. Returns false on any decode/verify failure. */
export function verifyDeviceSignature(
  publicKey: string,
  payload: string,
  signatureBase64Url: string,
): boolean {
  return verifyMlDsa65SignatureRaw({
    publicKey,
    payload,
    signatureBase64Url,
  });
}

/** Re-export the canonical ML-DSA-65 constants and prefix helpers so callers
 *  that previously imported them from this module keep working. */
export {
  MLDSA65_PUBLIC_KEY_LENGTH,
  MLDSA65_SECRET_KEY_LENGTH,
  isMlDsa65PublicKey,
  isMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  signMlDsa65Payload as signMlDsa65PayloadCanonical,
  verifyMlDsa65Signature as verifyMlDsa65SignatureCanonical,
} from "./mldsa65-key-storage.js";
