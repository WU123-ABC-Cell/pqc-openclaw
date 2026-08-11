// AES-256-GCM wrap/unwrap helpers for secrets at rest (PQC whitepaper 2.2).
//
// Why this exists: the device-identity store holds the ML-DSA-65 secret key
// in plaintext today. The whitepaper (2.2) requires that secret to be wrapped
// under a keyring-backed master key so an attacker who exfiltrates the
// `state/openclaw.sqlite` file does not also get signing material. The
// wrapped form lives in `device_identities.mldsa_private_key_wrapped` (BLOB)
// keyed by `mldsa_private_key_wrap_key_id` (TEXT, references the keyring).
//
// This module owns the cryptographic envelope only — the keyring lookup and
// the rotation / backup paths live in the M6+ keyring provider (see
// `keyring-provider.ts` once M6 lands). Tests for the wrap round-trip live
// in `secret-wrapping.test.ts` next to this file.
//
// Wire format — `WrappedSecret` (JSON-serialisable, all bytes base64url):
//   * `ciphertext` — AES-256-GCM ciphertext (no length padding, plaintext
//     size is recoverable from `unwrapSecret`).
//   * `iv` — 12-byte random nonce, freshly generated per `wrapSecret` call.
//     Re-using a (key, iv) pair catastrophically breaks GCM, so callers
//     MUST go through `wrapSecret` (never reuse the same `WrappedSecret`).
//   * `authTag` — 16-byte GCM auth tag produced by the cipher. AES-GCM
//     verifies the tag in `decipher.final`; tampered ciphertext OR iv OR
//     authTag throws on unwrap.
//   * `keyId` — names the keyring key that sealed the payload. Stored in
//     the row so a key rotation can re-encrypt the payload with the new
//     active key without losing the public side.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/** A wrapped secret ready to be stored in SQLite. All bytes are base64url. */
export interface WrappedSecret {
  /** AES-256-GCM ciphertext. */
  ciphertext: string;
  /** 12-byte GCM nonce. Fresh per wrap. */
  iv: string;
  /** 16-byte GCM authentication tag. */
  authTag: string;
  /** Keyring key id that sealed the payload. */
  keyId: string;
}

/** A 32-byte AES-256 key plus its keyring id. */
export interface ActiveWrappingKey {
  key: Buffer;
  keyId: string;
}

/** Contract that keyring providers (M6+) must satisfy. Inlined here so the
 *  wrap/unwrap helpers do not need to import the keyring module — this lets
 *  the helpers stay in `src/security/` and the keyring live elsewhere. */
export interface WrappingKeyProvider {
  /** Return the currently-active 32-byte key plus its keyring id. */
  getActiveKey(): ActiveWrappingKey;
  /** Look up a historical key by id, or null if the key is no longer
   *  available (rotated out, file deleted, OS keyring cleared). */
  getKeyById(keyId: string): Buffer | null;
}

/** AES-256-GCM requires a 32-byte key. Anything else is a keyring bug. */
const REQUIRED_KEY_BYTES = 32;
/** GCM standard nonce length. Re-using (key, iv) breaks GCM. */
const REQUIRED_IV_BYTES = 12;
/** GCM standard auth-tag length. */
const REQUIRED_AUTH_TAG_BYTES = 16;

/** Wrap `plaintext` under the provider's active key. The returned
 *  `WrappedSecret` is JSON-serialisable; pass it through
 *  `serializeWrappedSecret` to flatten it into a single base64url string
 *  for the SQLite BLOB column. */
export function wrapSecret(
  plaintext: Buffer,
  provider: WrappingKeyProvider,
): WrappedSecret {
  if (!Buffer.isBuffer(plaintext)) {
    throw new TypeError("wrapSecret: plaintext must be a Buffer");
  }
  const { key, keyId } = provider.getActiveKey();
  if (key.length !== REQUIRED_KEY_BYTES) {
    // Defence-in-depth: a keyring that hands us a wrong-size key is
    // misconfigured; refuse to encrypt rather than let GCM truncate or
    // pad silently. The message names the actual size so operators can
    // diagnose.
    throw new Error(
      `wrapSecret: wrapping key must be ${REQUIRED_KEY_BYTES} bytes (AES-256), got ${key.length}`,
    );
  }
  const iv = randomBytes(REQUIRED_IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  if (authTag.length !== REQUIRED_AUTH_TAG_BYTES) {
    // GCM's auth tag is always 16 bytes; if Node ever returns something
    // different, we'd be storing a partial tag and any verification
    // would silently weaken. Refuse the write.
    throw new Error(
      `wrapSecret: AES-256-GCM auth tag must be ${REQUIRED_AUTH_TAG_BYTES} bytes, got ${authTag.length}`,
    );
  }
  return {
    ciphertext: ciphertext.toString("base64url"),
    iv: iv.toString("base64url"),
    authTag: authTag.toString("base64url"),
    keyId,
  };
}

/** Unwrap a `WrappedSecret` back to its plaintext Buffer. Throws on:
 *  - missing key (keyId not in the keyring, or rotated out)
 *  - wrong key length
 *  - tampered ciphertext / iv / authTag (GCM verification failure)
 *  - malformed base64url / JSON shape
 *  The thrown error names the keyId so log analysis can attribute failures
 *  to a specific keyring entry without leaking the ciphertext itself. */
export function unwrapSecret(
  wrapped: WrappedSecret,
  provider: WrappingKeyProvider,
): Buffer {
  const key = provider.getKeyById(wrapped.keyId);
  if (!key) {
    throw new Error(`unwrapSecret: wrapping key not found: ${wrapped.keyId}`);
  }
  if (key.length !== REQUIRED_KEY_BYTES) {
    throw new Error(
      `unwrapSecret: wrapping key must be ${REQUIRED_KEY_BYTES} bytes (AES-256), got ${key.length}`,
    );
  }
  // Decode all three base64url fields up front so a malformed envelope
  // fails fast with a precise field name, before we touch the cipher.
  const iv = Buffer.from(wrapped.iv, "base64url");
  const authTag = Buffer.from(wrapped.authTag, "base64url");
  const ciphertext = Buffer.from(wrapped.ciphertext, "base64url");
  if (iv.length !== REQUIRED_IV_BYTES) {
    throw new Error(
      `unwrapSecret: iv must be ${REQUIRED_IV_BYTES} bytes, got ${iv.length}`,
    );
  }
  if (authTag.length !== REQUIRED_AUTH_TAG_BYTES) {
    throw new Error(
      `unwrapSecret: authTag must be ${REQUIRED_AUTH_TAG_BYTES} bytes, got ${authTag.length}`,
    );
  }
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  // GCM's `final()` runs the authentication check. Any tamper in
  // ciphertext / iv / authTag / key throws here — that is the canonical
  // failure path and is the one the test suite asserts.
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Flatten a `WrappedSecret` into a single base64url-encoded JSON string.
 *  This is the on-disk shape the `device_identities.mldsa_private_key_wrapped`
 *  BLOB column stores; the JSON is UTF-8 → base64url so SQLite sees raw
 *  bytes (no JSON1 extension required). */
export function serializeWrappedSecret(wrapped: WrappedSecret): string {
  return Buffer.from(JSON.stringify(wrapped), "utf8").toString("base64url");
}

/** Inverse of `serializeWrappedSecret`. Throws on:
 *  - non-base64url input (returns empty Buffer)
 *  - non-UTF-8 JSON payload
 *  - JSON shape missing any of `ciphertext` / `iv` / `authTag` / `keyId`
 *  - any field with the wrong type
 *  The defensive validation here is what lets a tampered SQLite BLOB
 *  fail closed at load time instead of crashing deeper in the keyring
 *  path. */
export function deserializeWrappedSecret(serialized: string): WrappedSecret {
  if (typeof serialized !== "string" || serialized.length === 0) {
    throw new Error("deserializeWrappedSecret: input must be a non-empty string");
  }
  const json = Buffer.from(serialized, "base64url").toString("utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (error) {
    throw new Error(
      `deserializeWrappedSecret: wrapped-secret JSON is malformed: ${(error as Error).message}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("deserializeWrappedSecret: wrapped-secret JSON must be an object");
  }
  const obj = parsed as Record<string, unknown>;
  const { ciphertext, iv, authTag, keyId } = obj;
  if (typeof ciphertext !== "string") {
    throw new Error("deserializeWrappedSecret: ciphertext must be a string");
  }
  if (typeof iv !== "string") {
    throw new Error("deserializeWrappedSecret: iv must be a string");
  }
  if (typeof authTag !== "string") {
    throw new Error("deserializeWrappedSecret: authTag must be a string");
  }
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new Error("deserializeWrappedSecret: keyId must be a non-empty string");
  }
  return { ciphertext, iv, authTag, keyId };
}
