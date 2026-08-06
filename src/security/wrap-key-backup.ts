// PQC step 2.3.5.D: wrap-key backup/restore helpers.
//
// Export: encrypts a 32-byte wrap key with a user-provided passphrase
//         (PBKDF2-SHA256 + AES-256-GCM) into a self-describing JSON blob.
// Import: decrypts the blob back into a 32-byte wrap key.
//
// The blob is intended to be stored in a password manager (1Password,
// Bitwarden, etc.) or printed on paper as a disaster-recovery backup.

import {
  pbkdf2Sync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";

const BACKUP_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000; // OWASP 2023 recommendation
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = "sha256";
const SALT_BYTES = 16;
const IV_BYTES = 12;
const WRAP_KEY_BYTES = 32;

export interface ExportedWrapKey {
  version: number;
  keyId: string;
  algorithm: "aes-256-gcm";
  kdf: "pbkdf2-sha256";
  iterations: number;
  salt: string;        // base64url
  iv: string;          // base64url
  ciphertext: string;  // base64url (32 bytes plaintext wrap key)
  authTag: string;     // base64url
}

export interface ExportOptions {
  passphrase: string;
  /** Override the PBKDF2 iteration count (default 600_000). */
  iterations?: number;
}

export interface ImportOptions {
  passphrase: string;
}

export interface ImportResult {
  key: Buffer;
  keyId: string;
}

export class WrapKeyBackupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WrapKeyBackupError";
  }
}

/** Export a 32-byte wrap key into an encrypted, self-describing blob. */
export function exportWrapKey(
  key: Buffer,
  keyId: string,
  options: ExportOptions,
): ExportedWrapKey {
  if (key.length !== WRAP_KEY_BYTES) {
    throw new WrapKeyBackupError(
      `wrap key must be ${WRAP_KEY_BYTES} bytes, got ${key.length}`,
    );
  }
  if (!options.passphrase || options.passphrase.length === 0) {
    throw new WrapKeyBackupError("passphrase must be a non-empty string");
  }

  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const iterations = options.iterations ?? PBKDF2_ITERATIONS;
  const derivedKey = pbkdf2Sync(
    options.passphrase,
    salt,
    iterations,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST,
  );

  const cipher = createCipheriv("aes-256-gcm", derivedKey, iv);
  const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    version: BACKUP_VERSION,
    keyId,
    algorithm: "aes-256-gcm",
    kdf: "pbkdf2-sha256",
    iterations,
    salt: salt.toString("base64url"),
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    authTag: authTag.toString("base64url"),
  };
}

/** Decrypt a backup blob back into a 32-byte wrap key. */
export function importWrapKey(
  blob: ExportedWrapKey,
  options: ImportOptions,
): ImportResult {
  if (blob.version !== BACKUP_VERSION) {
    throw new WrapKeyBackupError(`unsupported backup version: ${blob.version}`);
  }
  if (blob.algorithm !== "aes-256-gcm") {
    throw new WrapKeyBackupError(`unsupported algorithm: ${blob.algorithm}`);
  }
  if (blob.kdf !== "pbkdf2-sha256") {
    throw new WrapKeyBackupError(`unsupported kdf: ${blob.kdf}`);
  }
  if (!options.passphrase || options.passphrase.length === 0) {
    throw new WrapKeyBackupError("passphrase must be a non-empty string");
  }
  if (blob.iterations < 1_000 || blob.iterations > 10_000_000) {
    throw new WrapKeyBackupError(
      `iterations out of bounds (1000..10000000): ${blob.iterations}`,
    );
  }

  const salt = Buffer.from(blob.salt, "base64url");
  const iv = Buffer.from(blob.iv, "base64url");
  const derivedKey = pbkdf2Sync(
    options.passphrase,
    salt,
    blob.iterations,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST,
  );

  const decipher = createDecipheriv("aes-256-gcm", derivedKey, iv);
  decipher.setAuthTag(Buffer.from(blob.authTag, "base64url"));

  let key: Buffer;
  try {
    key = Buffer.concat([
      decipher.update(Buffer.from(blob.ciphertext, "base64url")),
      decipher.final(),
    ]);
  } catch {
    throw new WrapKeyBackupError(
      "decryption failed (wrong passphrase or tampered blob)",
    );
  }

  if (key.length !== WRAP_KEY_BYTES) {
    throw new WrapKeyBackupError(
      `decrypted key is not ${WRAP_KEY_BYTES} bytes: got ${key.length}`,
    );
  }

  return { key, keyId: blob.keyId };
}

/** Serialize a backup blob to a single base64url string (for password managers). */
export function serializeBackup(blob: ExportedWrapKey): string {
  return Buffer.from(JSON.stringify(blob), "utf8").toString("base64url");
}

/** Parse a base64url-encoded backup blob string. */
export function deserializeBackup(serialized: string): ExportedWrapKey {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(serialized, "base64url").toString("utf8"));
  } catch {
    throw new WrapKeyBackupError("invalid backup string: not base64url JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new WrapKeyBackupError("invalid backup string: not an object");
  }
  return parsed as ExportedWrapKey;
}
