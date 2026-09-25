import { randomBytes } from "node:crypto";
// OpenClaw PQC DM v1 authenticated hybrid envelope.
//
// This is intentionally NOT presented as standard NIP-44. NIP-44 does not
// define a post-quantum extension and is not a drop-in NIP-04 replacement.
// The construction reuses the reviewed NIP-44 v2 message-key, padding,
// ChaCha20 and HMAC structure while defining an explicit OpenClaw wire profile.
import { chacha20 } from "@noble/ciphers/chacha.js";
import { expand, hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

export const OPENCLAW_PQC_DM_PREFIX = "ocpqc1:";
export const OPENCLAW_PQC_DM_VERSION = 1;
export const OPENCLAW_PQC_DM_EVENT_KIND = 4444;
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_CIPHERTEXT_BYTES = 1088;

const NONCE_BYTES = 32;
const MAC_BYTES = 32;
const MAX_PLAINTEXT_BYTES = 0xffff;
const DOMAIN = new TextEncoder().encode("openclaw-pqc-dm-v1");
const MIN_RAW_ENVELOPE_BYTES = 1 + NONCE_BYTES + ML_KEM_768_CIPHERTEXT_BYTES + 2 + 32 + MAC_BYTES;
const MAX_RAW_ENVELOPE_BYTES =
  1 + NONCE_BYTES + ML_KEM_768_CIPHERTEXT_BYTES + 2 + 0x10000 + MAC_BYTES;

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function assertLength(name: string, value: Uint8Array, expected: number): void {
  if (value.length !== expected) {
    throw new Error(`${name} must be ${expected} bytes, got ${value.length}`);
  }
}

function decodeNostrPubkey(name: string, value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${name} must be a lowercase 64-character hex Nostr public key`);
  }
  return new Uint8Array(Buffer.from(value, "hex"));
}

function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function decodeCanonicalBase64Url(name: string, value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new Error(`${name} must use unpadded canonical base64url`);
  }
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (encodeBase64Url(decoded) !== value) {
    throw new Error(`${name} must use unpadded canonical base64url`);
  }
  return decoded;
}

function calcPaddedLength(unpaddedLength: number): number {
  if (unpaddedLength <= 32) {
    return 32;
  }
  const nextPower = 2 ** (Math.floor(Math.log2(unpaddedLength - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((unpaddedLength - 1) / chunk) + 1);
}

function pad(plaintext: Uint8Array): Uint8Array {
  if (plaintext.length < 1 || plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new Error(
      `OpenClaw PQC DM plaintext must be 1..${MAX_PLAINTEXT_BYTES} bytes, got ${plaintext.length}`,
    );
  }
  const paddedLength = calcPaddedLength(plaintext.length);
  const out = new Uint8Array(2 + paddedLength);
  out[0] = plaintext.length >>> 8;
  out[1] = plaintext.length & 0xff;
  out.set(plaintext, 2);
  return out;
}

function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < 34) {
    throw new Error("OpenClaw PQC DM padded plaintext is too short");
  }
  const plaintextLength = (padded[0]! << 8) | padded[1]!;
  if (
    plaintextLength < 1 ||
    plaintextLength > MAX_PLAINTEXT_BYTES ||
    padded.length !== 2 + calcPaddedLength(plaintextLength)
  ) {
    throw new Error("OpenClaw PQC DM padding is invalid");
  }
  const plaintext = padded.slice(2, 2 + plaintextLength);
  for (let index = 2 + plaintextLength; index < padded.length; index += 1) {
    if (padded[index] !== 0) {
      throw new Error("OpenClaw PQC DM padding is invalid");
    }
  }
  return plaintext;
}

function buildIdentityContext(senderPubkey: string, recipientPubkey: string): Uint8Array {
  return concatBytes(
    DOMAIN,
    decodeNostrPubkey("senderPubkey", senderPubkey),
    decodeNostrPubkey("recipientPubkey", recipientPubkey),
  );
}

function deriveHybridConversationKey(input: {
  classicalConversationKey: Uint8Array;
  mlKemSharedSecret: Uint8Array;
  mlKemCiphertext: Uint8Array;
  identityContext: Uint8Array;
}): Uint8Array {
  assertLength("classicalConversationKey", input.classicalConversationKey, 32);
  assertLength("mlKemSharedSecret", input.mlKemSharedSecret, 32);
  assertLength("mlKemCiphertext", input.mlKemCiphertext, ML_KEM_768_CIPHERTEXT_BYTES);
  const ikm = concatBytes(
    input.classicalConversationKey,
    input.mlKemSharedSecret,
    input.mlKemCiphertext,
  );
  try {
    return hkdf(sha256, ikm, DOMAIN, input.identityContext, 32);
  } finally {
    ikm.fill(0);
  }
}

function deriveMessageKeys(
  conversationKey: Uint8Array,
  nonce: Uint8Array,
): {
  chachaKey: Uint8Array;
  chachaNonce: Uint8Array;
  hmacKey: Uint8Array;
} {
  assertLength("conversationKey", conversationKey, 32);
  assertLength("nonce", nonce, NONCE_BYTES);
  const keys = expand(sha256, conversationKey, nonce, 76);
  return {
    chachaKey: keys.slice(0, 32),
    chachaNonce: keys.slice(32, 44),
    hmacKey: keys.slice(44, 76),
  };
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function computeMac(input: {
  hmacKey: Uint8Array;
  nonce: Uint8Array;
  mlKemCiphertext: Uint8Array;
  ciphertext: Uint8Array;
  identityContext: Uint8Array;
}): Uint8Array {
  const authenticated = concatBytes(
    Uint8Array.of(OPENCLAW_PQC_DM_VERSION),
    input.nonce,
    input.mlKemCiphertext,
    input.ciphertext,
    input.identityContext,
  );
  try {
    return hmac(sha256, input.hmacKey, authenticated);
  } finally {
    authenticated.fill(0);
  }
}

export function generateMlKem768KeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}

export function deriveMlKem768PublicKey(secretKey: Uint8Array): Uint8Array {
  assertLength("ML-KEM-768 secret key", secretKey, ML_KEM_768_SECRET_KEY_BYTES);
  return ml_kem768.getPublicKey(secretKey);
}

export function encodeMlKemKey(bytes: Uint8Array): string {
  return encodeBase64Url(bytes);
}

export function decodeMlKem768PublicKey(value: string): Uint8Array {
  const key = decodeCanonicalBase64Url("ML-KEM-768 public key", value);
  assertLength("ML-KEM-768 public key", key, ML_KEM_768_PUBLIC_KEY_BYTES);
  return key;
}

export function decodeMlKem768SecretKey(value: string): Uint8Array {
  const key = decodeCanonicalBase64Url("ML-KEM-768 secret key", value);
  assertLength("ML-KEM-768 secret key", key, ML_KEM_768_SECRET_KEY_BYTES);
  return key;
}

export interface OpenClawPqcDmEncryptInput {
  classicalConversationKey: Uint8Array;
  recipientMlKemPublicKey: Uint8Array;
  senderPubkey: string;
  recipientPubkey: string;
  plaintext: string;
}

export function encryptOpenClawPqcDmV1(input: OpenClawPqcDmEncryptInput): string {
  assertLength(
    "recipientMlKemPublicKey",
    input.recipientMlKemPublicKey,
    ML_KEM_768_PUBLIC_KEY_BYTES,
  );
  const identityContext = buildIdentityContext(input.senderPubkey, input.recipientPubkey);
  const encapsulated = ml_kem768.encapsulate(input.recipientMlKemPublicKey);
  const nonce = new Uint8Array(randomBytes(NONCE_BYTES));
  const conversationKey = deriveHybridConversationKey({
    classicalConversationKey: input.classicalConversationKey,
    mlKemSharedSecret: encapsulated.sharedSecret,
    mlKemCiphertext: encapsulated.cipherText,
    identityContext,
  });
  const { chachaKey, chachaNonce, hmacKey } = deriveMessageKeys(conversationKey, nonce);
  let padded: Uint8Array | undefined;
  try {
    padded = pad(new TextEncoder().encode(input.plaintext));
    const ciphertext = chacha20(chachaKey, chachaNonce, padded);
    const mac = computeMac({
      hmacKey,
      nonce,
      mlKemCiphertext: encapsulated.cipherText,
      ciphertext,
      identityContext,
    });
    const raw = concatBytes(
      Uint8Array.of(OPENCLAW_PQC_DM_VERSION),
      nonce,
      encapsulated.cipherText,
      ciphertext,
      mac,
    );
    return `${OPENCLAW_PQC_DM_PREFIX}${encodeBase64Url(raw)}`;
  } finally {
    encapsulated.sharedSecret.fill(0);
    conversationKey.fill(0);
    chachaKey.fill(0);
    chachaNonce.fill(0);
    hmacKey.fill(0);
    padded?.fill(0);
  }
}

export interface OpenClawPqcDmDecryptInput {
  classicalConversationKey: Uint8Array;
  recipientMlKemSecretKey: Uint8Array;
  senderPubkey: string;
  recipientPubkey: string;
  envelope: string;
}

export function decryptOpenClawPqcDmV1(input: OpenClawPqcDmDecryptInput): string {
  assertLength(
    "recipientMlKemSecretKey",
    input.recipientMlKemSecretKey,
    ML_KEM_768_SECRET_KEY_BYTES,
  );
  if (!input.envelope.startsWith(OPENCLAW_PQC_DM_PREFIX)) {
    throw new Error(`OpenClaw PQC DM envelope must start with ${OPENCLAW_PQC_DM_PREFIX}`);
  }
  const encoded = input.envelope.slice(OPENCLAW_PQC_DM_PREFIX.length);
  const raw = decodeCanonicalBase64Url("OpenClaw PQC DM envelope", encoded);
  if (raw.length < MIN_RAW_ENVELOPE_BYTES || raw.length > MAX_RAW_ENVELOPE_BYTES) {
    throw new Error("OpenClaw PQC DM envelope has an invalid size");
  }
  if (raw[0] !== OPENCLAW_PQC_DM_VERSION) {
    throw new Error(`Unsupported OpenClaw PQC DM version ${raw[0]}`);
  }
  const nonceStart = 1;
  const kemStart = nonceStart + NONCE_BYTES;
  const ciphertextStart = kemStart + ML_KEM_768_CIPHERTEXT_BYTES;
  const macStart = raw.length - MAC_BYTES;
  const nonce = raw.slice(nonceStart, kemStart);
  const mlKemCiphertext = raw.slice(kemStart, ciphertextStart);
  const ciphertext = raw.slice(ciphertextStart, macStart);
  const mac = raw.slice(macStart);
  const identityContext = buildIdentityContext(input.senderPubkey, input.recipientPubkey);
  const mlKemSharedSecret = ml_kem768.decapsulate(mlKemCiphertext, input.recipientMlKemSecretKey);
  const conversationKey = deriveHybridConversationKey({
    classicalConversationKey: input.classicalConversationKey,
    mlKemSharedSecret,
    mlKemCiphertext,
    identityContext,
  });
  const { chachaKey, chachaNonce, hmacKey } = deriveMessageKeys(conversationKey, nonce);
  let padded: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    const expectedMac = computeMac({
      hmacKey,
      nonce,
      mlKemCiphertext,
      ciphertext,
      identityContext,
    });
    if (!constantTimeEqual(mac, expectedMac)) {
      throw new Error("OpenClaw PQC DM authentication failed");
    }
    padded = chacha20(chachaKey, chachaNonce, ciphertext);
    plaintext = unpad(padded);
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } finally {
    mlKemSharedSecret.fill(0);
    conversationKey.fill(0);
    chachaKey.fill(0);
    chachaNonce.fill(0);
    hmacKey.fill(0);
    padded?.fill(0);
    plaintext?.fill(0);
  }
}

export function isOpenClawPqcDmEnvelope(value: string): boolean {
  return value.startsWith(OPENCLAW_PQC_DM_PREFIX);
}
