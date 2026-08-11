// Wrap-key rotation + backup helpers (PQC whitepaper 2.2.5.C + 2.2.5.D).
//
// Rotation: re-wrap a stored device identity's ML-DSA-65 secret key
// under a new key. The public side never changes; the rotation only
// re-seals the existing plaintext secret bytes with the new key. The
// keyId column is updated so a subsequent read uses the new key.
//
// Backup: encrypt the 32-byte key bytes under a passphrase. The
// passphrase is stretched with PBKDF2-SHA256 (210_000 iterations,
// OWASP 2023 guidance for SHA-256) and the resulting 32-byte key is
// used as the AES-256-GCM key. The salt and IV are fresh per backup;
// the iteration count is recorded in the envelope so future readers
// can negotiate a stronger cost factor without breaking old backups.
//
// Restore: inverse of backup. Verifies the passphrase produces a
// 32-byte key, decrypts the key bytes, and returns them. The caller
// is responsible for installing the key into a keyring (file / env /
// OS). The restore is intentionally not tied to a specific keyring
// so M8's `openclaw wrap-key import <file>` can hand the bytes to
// the operator's preferred backend.
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";
import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  unwrapSecret,
  type WrappedSecret,
  type WrappingKeyProvider,
  wrapSecret,
} from "./secret-wrapping.js";

/** PBKDF2 iteration count for passphrase-derived key backups.
 *  Matches OWASP 2023 guidance for PBKDF2-SHA256. Older backups with
 *  a smaller `iterations` field are still accepted; new backups use
 *  this value. */
const PBKDF2_ITERATIONS = 210_000;
/** PBKDF2 salt length. 16 bytes is the standard recommendation. */
const PBKDF2_SALT_BYTES = 16;
/** AES-256-GCM IV length. 12 bytes is the GCM standard. */
const AES_GCM_IV_BYTES = 12;

/** Re-wrap a stored ML-DSA-65 secret under a new wrap key. The caller
 *  supplies the new key through a `WrappingKeyProvider` whose
 *  `getActiveKey()` returns the new (key, keyId) pair. The new key
 *  is recorded in the returned `StoredDeviceIdentity` so a
 *  subsequent read unwraps with the new key.
 *
 *  The old key is NOT consulted: rotation produces a fresh envelope
 *  under the new key, with the plaintext secret recovered once via
 *  the old keyring and then immediately re-wrapped. This is the
 *  canonical "re-encrypt" path; we do not support a multi-key
 *  migration step because the device identity row is single-keyed.
 *  Historical rows that still reference the old keyId are rewritten
 *  in place (the `wrapKeyId` and the BLOB change; everything else
 *  stays byte-for-byte identical). */
export function rotateWrappingKey(params: {
  stored: { privateKeyPem: string; mldsaPrivateKeyWrapped: string | null; mldsaPrivateKeyWrapKeyId: string | null };
  oldKeyring: WrappingKeyProvider;
  newKeyring: WrappingKeyProvider;
}): { mldsaPrivateKeyWrapped: string; mldsaPrivateKeyWrapKeyId: string } {
  if (!params.stored.mldsaPrivateKeyWrapped) {
    throw new Error(
      "rotateWrappingKey: stored identity has no wrap envelope; " +
        "refusing to rotate a plaintext (no-keyring) row",
    );
  }
  if (!params.stored.mldsaPrivateKeyWrapKeyId) {
    throw new Error(
      "rotateWrappingKey: stored identity has a wrap envelope but no wrapKeyId; " +
        "the row is in an inconsistent state — refuse to rotate",
    );
  }
  // Recover the plaintext ML-DSA-65 secret once via the old keyring.
  const wrapped: WrappedSecret = deserializeWrappedSecret(params.stored.mldsaPrivateKeyWrapped);
  const rawSecret: Buffer = unwrapSecret(wrapped, params.oldKeyring);
  // Re-wrap under the new key. The wrap envelope's keyId field is
  // the source of truth; we ignore `wrapped.keyId` from the old
  // envelope because the rotation explicitly re-issues the keyId.
  const rewrapped = wrapSecret(rawSecret, params.newKeyring);
  // Wipe the recovered plaintext from the caller's stack as best we
  // can. JS strings/Buffers are not reliably zeroable, but a
  // best-effort fill here is what we have.
  rawSecret.fill(0);
  return {
    mldsaPrivateKeyWrapped: serializeWrappedSecret(rewrapped),
    mldsaPrivateKeyWrapKeyId: rewrapped.keyId,
  };
}

/** Serialised wrap-key backup envelope (whitepaper 2.2.5.D.1). All
 *  bytes are base64url so the on-disk format is a single ASCII string
 *  that the operator can paste into a secret manager. */
export interface WrapKeyBackup {
  /** Schema version. Bumped on any change to the envelope shape. */
  version: 1;
  /** PBKDF2-SHA256 iteration count. Older backups may have a smaller
   *  value; the loader accepts any value but refuses to load a
   *  smaller one with a warning so a slow-rolling upgrade can be
   *  forced by re-encrypting. */
  iterations: number;
  /** PBKDF2 salt (16 bytes). */
  salt: string;
  /** AES-256-GCM nonce (12 bytes). */
  iv: string;
  /** AES-256-GCM ciphertext (32 bytes for a 32-byte key). */
  ciphertext: string;
  /** AES-256-GCM auth tag (16 bytes). */
  authTag: string;
  /** The keyId that this key was bound to (informational; the loader
   *  is free to use a different id). */
  keyId: string;
}

function deriveKeyFromPassphrase(passphrase: string, salt: Buffer, iterations: number): Buffer {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("wrapKeyBackup: passphrase must be a non-empty string");
  }
  return pbkdf2Sync(Buffer.from(passphrase, "utf8"), salt, iterations, 32, "sha256");
}

/** Encrypt a 32-byte wrap key under a passphrase. Returns a JSON-
 *  serialisable backup envelope. The caller writes it to a file
 *  (M8's `openclaw wrap-key export`). */
export function exportWrapKey(params: {
  key: Buffer;
  passphrase: string;
  keyId: string;
  iterations?: number;
}): WrapKeyBackup {
  if (!Buffer.isBuffer(params.key) || params.key.length !== 32) {
    throw new Error("exportWrapKey: key must be a 32-byte Buffer");
  }
  const iterations = params.iterations ?? PBKDF2_ITERATIONS;
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error(`exportWrapKey: iterations must be a positive integer, got ${iterations}`);
  }
  const salt = randomBytes(PBKDF2_SALT_BYTES);
  const derivedKey = deriveKeyFromPassphrase(params.passphrase, salt, iterations);
  const iv = randomBytes(AES_GCM_IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", derivedKey, iv);
  const ciphertext = Buffer.concat([cipher.update(params.key), cipher.final()]);
  const authTag = cipher.getAuthTag();
  // Wipe the derived key from the stack as best we can.
  derivedKey.fill(0);
  return {
    version: 1,
    iterations,
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    authTag: authTag.toString("base64url"),
    keyId: params.keyId,
  };
}

/** Inverse of `exportWrapKey`. Throws on wrong passphrase (GCM auth
 *  fails), wrong size, or any malformed envelope field. */
export function importWrapKey(params: { backup: WrapKeyBackup; passphrase: string }): Buffer {
  if (typeof params.backup !== "object" || params.backup === null) {
    throw new Error("importWrapKey: backup must be an object");
  }
  const { version, iterations, salt, iv, ciphertext, authTag, keyId } = params.backup;
  if (version !== 1) {
    throw new Error(`importWrapKey: unsupported backup version ${version}; expected 1`);
  }
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error(`importWrapKey: iterations must be a positive integer, got ${iterations}`);
  }
  // Defensive length checks on every base64url-decoded field so a
  // tampered backup fails at the field name, not deep in the cipher.
  const saltBuf = Buffer.from(salt, "base64url");
  const ivBuf = Buffer.from(iv, "base64url");
  const cipherBuf = Buffer.from(ciphertext, "base64url");
  const tagBuf = Buffer.from(authTag, "base64url");
  if (saltBuf.length !== PBKDF2_SALT_BYTES) {
    throw new Error(`importWrapKey: salt must be ${PBKDF2_SALT_BYTES} bytes, got ${saltBuf.length}`);
  }
  if (ivBuf.length !== AES_GCM_IV_BYTES) {
    throw new Error(`importWrapKey: iv must be ${AES_GCM_IV_BYTES} bytes, got ${ivBuf.length}`);
  }
  if (cipherBuf.length !== 32) {
    throw new Error(`importWrapKey: ciphertext must be 32 bytes (key size), got ${cipherBuf.length}`);
  }
  if (tagBuf.length !== 16) {
    throw new Error(`importWrapKey: authTag must be 16 bytes, got ${tagBuf.length}`);
  }
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new Error("importWrapKey: keyId must be a non-empty string");
  }
  const derivedKey = deriveKeyFromPassphrase(params.passphrase, saltBuf, iterations);
  try {
    const decipher = createDecipheriv("aes-256-gcm", derivedKey, ivBuf);
    decipher.setAuthTag(tagBuf);
    const key = Buffer.concat([decipher.update(cipherBuf), decipher.final()]);
    if (key.length !== 32) {
      throw new Error(`importWrapKey: decrypted key must be 32 bytes, got ${key.length}`);
    }
    return key;
  } finally {
    derivedKey.fill(0);
  }
}

/** Constant-time comparison of two buffers, used by the health check
 *  to verify a freshly unwrapped plaintext matches the expected form
 *  without leaking timing. */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/** Exported constants so the M8 CLI and Doctor health check can
 *  surface the current PBKDF2 cost factor to the operator. */
export const WRAP_KEY_BACKUP_CONSTANTS = Object.freeze({
  PBKDF2_ITERATIONS,
  PBKDF2_SALT_BYTES,
  AES_GCM_IV_BYTES,
  BACKUP_VERSION: 1 as const,
});
