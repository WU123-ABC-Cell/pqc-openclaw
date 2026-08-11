// FIPS 204 ML-DSA-65 key storage and sign/verify helpers backed by @noble/post-quantum.
//
// This module owns the only legitimate path to ML-DSA-65 key material in the fork.
// It deliberately avoids any Ed25519 fallback so callers cannot accidentally downgrade
// to a classical algorithm at runtime.
//
// Why @noble and not Node native crypto?
//   Node 22's `node:crypto` does NOT expose ML-DSA-65 in its JS API even though the
//   bundled OpenSSL 3.5+ has the primitives. ML-DSA-65 key generation / signing
//   was added to Node's JS API in v24.6.0 (see OpenSSL v26 docs). Since the
//   fork's runtime is pinned to Node 22.x (matching the upstream OpenClaw 2026.7.2
//   LTS), the only FIPS 204 implementation available in pure JS is @noble/post-quantum.
//   We accept the small supply-chain surface in exchange for staying on Node 22
//   and matching what the whitepaper (§2.1, FIPS 204) requires.
//
// Storage format: the public/secret-key raw bytes are base64url-encoded and tagged
// with a stable, parseable prefix ("MLDSA65-PUBLIC-KEY:" / "MLDSA65-SECRET-KEY:").
// The prefix is what the device-identity SQLite store round-trips through, so a
// future swap to a different post-quantum algorithm only has to change the prefix.
import crypto from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

/** FIPS 204 §4 Table 1 parameter set lengths (parameter 6 = ML-DSA-65). */
export const MLDSA65_PUBLIC_KEY_LENGTH = 1952;
export const MLDSA65_SECRET_KEY_LENGTH = 4032;
export const MLDSA65_SIGNATURE_LENGTH = 3309;
export const MLDSA65_MAX_MESSAGE_BYTES = 1 << 20; // 1 MiB sanity cap, generous for FIPS 204

const PUBLIC_KEY_PREFIX = "MLDSA65-PUBLIC-KEY:";
const SECRET_KEY_PREFIX = "MLDSA65-SECRET-KEY:";

export type MlDsa65KeyPair = {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
};

export type MlDsa65SerializedKeyPair = {
  publicKey: string; // "MLDSA65-PUBLIC-KEY:<base64url raw bytes>"
  secretKey: string; // "MLDSA65-SECRET-KEY:<base64url raw bytes>"
};

function asBuffer(bytes: Uint8Array): Buffer {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function assertLength(actual: number, expected: number, label: string): void {
  if (actual !== expected) {
    throw new Error(
      `ML-DSA-65 ${label} must be exactly ${expected} bytes (FIPS 204), got ${actual}`,
    );
  }
}

/**
 * Generate a fresh ML-DSA-65 keypair. @noble uses OS entropy by default
 * (FIPS 204 §5.3 hedged signing path; the entropy is consumed at sign time, not keygen).
 */
export function generateMlDsa65KeyPair(): MlDsa65KeyPair {
  const kp = ml_dsa65.keygen();
  assertLength(kp.publicKey.length, MLDSA65_PUBLIC_KEY_LENGTH, "public key");
  assertLength(kp.secretKey.length, MLDSA65_SECRET_KEY_LENGTH, "secret key");
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

function encodeKey(prefix: string, raw: Uint8Array): string {
  if (prefix === PUBLIC_KEY_PREFIX) {
    assertLength(raw.length, MLDSA65_PUBLIC_KEY_LENGTH, "public key");
  } else {
    assertLength(raw.length, MLDSA65_SECRET_KEY_LENGTH, "secret key");
  }
  return prefix + asBuffer(raw).toString("base64url");
}

function decodeKey(prefix: string, encoded: string, expectedLength: number): Uint8Array {
  if (!encoded.startsWith(prefix)) {
    throw new Error(`ML-DSA-65 key is missing required prefix "${prefix}"`);
  }
  const body = encoded.slice(prefix.length);
  if (body.length === 0) {
    throw new Error("ML-DSA-65 key body must not be empty");
  }
  const raw = new Uint8Array(Buffer.from(body, "base64url"));
  assertLength(raw.length, expectedLength, "decoded key");
  return raw;
}

export function encodeMlDsa65PublicKey(raw: Uint8Array): string {
  return encodeKey(PUBLIC_KEY_PREFIX, raw);
}

export function encodeMlDsa65SecretKey(raw: Uint8Array): string {
  return encodeKey(SECRET_KEY_PREFIX, raw);
}

export function decodeMlDsa65PublicKey(encoded: string): Uint8Array {
  return decodeKey(PUBLIC_KEY_PREFIX, encoded, MLDSA65_PUBLIC_KEY_LENGTH);
}

export function decodeMlDsa65SecretKey(encoded: string): Uint8Array {
  return decodeKey(SECRET_KEY_PREFIX, encoded, MLDSA65_SECRET_KEY_LENGTH);
}

export function serializeMlDsa65KeyPair(kp: MlDsa65KeyPair): MlDsa65SerializedKeyPair {
  return {
    publicKey: encodeMlDsa65PublicKey(kp.publicKey),
    secretKey: encodeMlDsa65SecretKey(kp.secretKey),
  };
}

export function deserializeMlDsa65KeyPair(serialized: MlDsa65SerializedKeyPair): MlDsa65KeyPair {
  return {
    publicKey: decodeMlDsa65PublicKey(serialized.publicKey),
    secretKey: decodeMlDsa65SecretKey(serialized.secretKey),
  };
}

export function isMlDsa65PublicKey(encoded: string): boolean {
  return typeof encoded === "string" && encoded.startsWith(PUBLIC_KEY_PREFIX);
}

export function isMlDsa65SecretKey(encoded: string): boolean {
  return typeof encoded === "string" && encoded.startsWith(SECRET_KEY_PREFIX);
}

export function fingerprintMlDsa65PublicKey(publicKey: Uint8Array): string {
  assertLength(publicKey.length, MLDSA65_PUBLIC_KEY_LENGTH, "public key");
  // SHA-256 of the raw 1952-byte public key, returned as 64 lowercase hex chars.
  // This keeps the `deviceId` shape compatible with the existing 64-char
  // SQLite column and the `/^[a-f0-9]{64}$/` validator in device-identity-store.
  return crypto.createHash("sha256").update(Buffer.from(publicKey)).digest("hex");
}

export type SignMlDsa65Options = {
  /**
   * FIPS 204 §5.3 allows hedged signing (randomized) for side-channel resistance.
   * @noble defaults to hedged; pass `deterministic: true` (alias of `extraEntropy: false`)
   * only for KAT / reproducibility. Production code must keep hedged signing.
   */
  deterministic?: boolean;
  /**
   * 32 bytes of caller-provided entropy to mix into the signature, or `false`
   * to opt out of randomization. When omitted, noble uses OS random (hedged).
   */
  extraEntropy?: Uint8Array | false;
};

function buildSignOpts(options: SignMlDsa65Options): { extraEntropy?: Uint8Array | false } {
  if (options.deterministic && options.extraEntropy !== undefined) {
    throw new Error(
      "ML-DSA-65 sign options: deterministic and extraEntropy are mutually exclusive",
    );
  }
  if (options.deterministic) {
    return { extraEntropy: false };
  }
  if (options.extraEntropy === undefined) {
    // No options → omit extraEntropy so noble uses OS random (FIPS 204 §5.3
    // hedged signing, the safe production default). Pass a Uint8Array to inject
    // test entropy, or `false` to opt into deterministic mode.
    return {};
  }
  return { extraEntropy: options.extraEntropy };
}

/** Sign raw `message` bytes. Returns raw 3309-byte signature. */
export function signMlDsa65(
  message: Uint8Array,
  secretKey: Uint8Array,
  options: SignMlDsa65Options = {},
): Uint8Array {
  assertLength(secretKey.length, MLDSA65_SECRET_KEY_LENGTH, "secret key");
  if (message.length > MLDSA65_MAX_MESSAGE_BYTES) {
    throw new Error(
      `ML-DSA-65 message exceeds ${MLDSA65_MAX_MESSAGE_BYTES} bytes (got ${message.length})`,
    );
  }
  const opts = buildSignOpts(options);
  const sig = ml_dsa65.sign(message, secretKey, opts);
  assertLength(sig.length, MLDSA65_SIGNATURE_LENGTH, "signature");
  return sig;
}

/** Verify a raw 3309-byte signature. Returns false on any decode/verify failure. */
export function verifyMlDsa65(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    if (signature.length !== MLDSA65_SIGNATURE_LENGTH) return false;
    if (publicKey.length !== MLDSA65_PUBLIC_KEY_LENGTH) return false;
    if (message.length > MLDSA65_MAX_MESSAGE_BYTES) return false;
    return ml_dsa65.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/** Sign `payload` (utf-8 text) with the given ML-DSA-65 secret key. Returns base64url(raw 3309 bytes). */
export function signMlDsa65Payload(
  secretKey: Uint8Array,
  payload: string,
  options: SignMlDsa65Options = {},
): string {
  const message = Buffer.from(payload, "utf8");
  const sig = signMlDsa65(message, secretKey, options);
  return Buffer.from(sig).toString("base64url");
}

/** Verify a base64url-encoded ML-DSA-65 signature. Returns false on any decode/verify failure. */
export function verifyMlDsa65Signature(params: {
  publicKey: string | Uint8Array;
  payload: string;
  signatureBase64Url: string;
  options?: SignMlDsa65Options;
}): boolean {
  try {
    const rawPublic = typeof params.publicKey === "string"
      ? decodeMlDsa65PublicKey(params.publicKey)
      : params.publicKey;
    const message = Buffer.from(params.payload, "utf8");
    if (message.length > MLDSA65_MAX_MESSAGE_BYTES) return false;
    // ML-DSA-65 sigs are 4412 base64url chars; bypass any 4096-char input cap that
    // may exist in canonical-base64url decoders and decode directly.
    const sig = new Uint8Array(Buffer.from(params.signatureBase64Url, "base64url"));
    return verifyMlDsa65(sig, message, rawPublic);
  } catch {
    return false;
  }
}
