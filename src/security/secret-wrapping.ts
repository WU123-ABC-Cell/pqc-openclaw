/**
 * Wraps/unwraps secret bytes with AES-256-GCM using a keyring-backed master
 * key. The WrappingKeyProvider abstracts over the actual key source (OS
 * keyring, passphrase-derived key, ML-KEM-768 unwrapped key, etc.).
 *
 * Each wrap records a keyId so a key can be rotated without losing the
 * ability to decrypt previously wrapped secrets.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface WrappedSecret {
  ciphertext: string; // base64url
  iv: string; // base64url, 12 bytes
  authTag: string; // base64url, 16 bytes
  keyId: string;
}

export interface ActiveWrappingKey {
  key: Buffer; // 32 bytes
  keyId: string;
}

export interface WrappingKeyProvider {
  getActiveKey(): ActiveWrappingKey;
  getKeyById(keyId: string): Buffer | null;
}

export function wrapSecret(
  plaintext: Buffer,
  provider: WrappingKeyProvider,
): WrappedSecret {
  const { key, keyId } = provider.getActiveKey();
  if (key.length !== 32) {
    throw new Error(`wrapping key must be 32 bytes, got ${key.length}`);
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: ciphertext.toString("base64url"),
    iv: iv.toString("base64url"),
    authTag: authTag.toString("base64url"),
    keyId,
  };
}

export function unwrapSecret(
  wrapped: WrappedSecret,
  provider: WrappingKeyProvider,
): Buffer {
  const key = provider.getKeyById(wrapped.keyId);
  if (!key) {
    throw new Error(`wrapping key not found: ${wrapped.keyId}`);
  }
  if (key.length !== 32) {
    throw new Error(`wrapping key must be 32 bytes, got ${key.length}`);
  }
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(wrapped.iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(wrapped.authTag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(wrapped.ciphertext, "base64url")),
    decipher.final(),
  ]);
}

/** Serialize a WrappedSecret into a single base64url JSON string for SQLite. */
export function serializeWrappedSecret(wrapped: WrappedSecret): string {
  return Buffer.from(JSON.stringify(wrapped), "utf8").toString("base64url");
}

/** Deserialize a WrappedSecret from a base64url JSON string. */
export function deserializeWrappedSecret(serialized: string): WrappedSecret {
  const parsed = JSON.parse(Buffer.from(serialized, "base64url").toString("utf8"));
  if (
    typeof parsed.ciphertext !== "string" ||
    typeof parsed.iv !== "string" ||
    typeof parsed.authTag !== "string" ||
    typeof parsed.keyId !== "string"
  ) {
    throw new Error("invalid WrappedSecret payload");
  }
  return parsed as WrappedSecret;
}
