// NIP-44 v2 + ML-KEM-768 hybrid (PQC whitepaper 1.1).
//
// Wire format (custom extension of NIP-44 v2):
//
//   <prefix><kem_ciphertext_b64url><chacha_ciphertext_b64url><mac_b64url>
//
//   prefix        = "pqc2:"   (custom; the upstream NIP-44 v2 wire is
//                              "2:<chacha_ciphertext_b64url><mac_b64url>")
//   kem_ct        = 1088-byte ML-KEM-768 ciphertext (base64url)
//   chacha_ct     = chacha20-padded-plaintext ciphertext (base64url)
//   mac           = 32-byte HMAC-SHA256 (base64url)
//
// The auto-detect path in the Nostr extension checks for the "pqc2:"
// prefix and decodes the ML-KEM-768 layer; everything else falls
// through to the upstream NIP-44 v1 / v2 / NIP-04 paths unchanged.
//
// Conversation key derivation per the NIP-44 v2 spec, with the
// shared-secret step extended to combine ECDH + ML-KEM-768:
//
//   shared_secret_e = secp256k1-ecdh(priv, peer_pub)        // 32 bytes
//   shared_secret_k = ml-kem-768-decaps(kem_ct, priv)       // 32 bytes
//   shared_secret   = shared_secret_e || shared_secret_k   // 64 bytes
//   conversation_key = HKDF-Extract(salt=conversation_key,
//                                   ikm=shared_secret,
//                                   info="nip44-v2")
//
//   chacha_key, chacha_nonce, hmac_key =
//     HKDF-Expand(L=76, info="nip44-v2", okm=conversation_key)
//
// Padded plaintext follows the NIP-44 v2 padding rule: prefix the
// plaintext with a 2-byte big-endian length, then pad with zero
// bytes to the next multiple of 32. The padding length is
// constrained to [1, 65535] (the spec's "1 <= plaintext_length <=
// 65535"). The 32-byte min comes from the spec's
// "longer than 32 bytes is never padded" rule.
import { chacha20 } from "@noble/ciphers/chacha.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";

/** Wire format prefix for the ML-KEM-768 + NIP-44 v2 hybrid envelope. */
export const PQC_NIP44_PREFIX = "pqc2:";
/** Upstream NIP-44 v2 prefix (no ML-KEM layer). Kept for reference. */
export const UPSTREAM_NIP44_V2_PREFIX = "2:";
/** ML-KEM-768 ciphertext size (FIPS 203 §8 parameter set 3). */
const ML_KEM_768_CIPHERTEXT_BYTES = 1088;
/** ML-KEM-768 shared-secret size. */
const ML_KEM_768_SHARED_SECRET_BYTES = 32;
/** NIP-44 v2 MAC size (HMAC-SHA256 truncated to 32 bytes). */
const NIP44_MAC_BYTES = 32;
/** NIP-44 v2 max plaintext size (uint16 length prefix). */
const NIP44_MAX_PLAINTEXT_BYTES = 0xffff;

/** Conversation key derivation per NIP-44 v2 + ML-KEM-768. */
function deriveConversationKey(sharedSecret: Uint8Array): Uint8Array {
  // HKDF-Extract with the upstream spec's salt = 0x00*32 ("conversation_key"
  // — a 32-byte zero string). info = "nip44-v2".
  return hkdf(
    sha256,
    sharedSecret,
    new Uint8Array(32), // salt
    new TextEncoder().encode("nip44-v2"),
    32, // L: 32 bytes
  );
}

/** Expand the conversation key into chacha_key (32) + chacha_nonce (12) + hmac_key (32). */
function deriveMessageKeys(conversationKey: Uint8Array): {
  chachaKey: Uint8Array;
  chachaNonce: Uint8Array;
  hmacKey: Uint8Array;
} {
  const okm = hkdf(
    sha256,
    conversationKey,
    new Uint8Array(32),
    new TextEncoder().encode("nip44-v2"),
    32 + 12 + 32, // 76 bytes total
  );
  return {
    chachaKey: okm.slice(0, 32),
    chachaNonce: okm.slice(32, 44),
    hmacKey: okm.slice(44, 76),
  };
}

/** NIP-44 v2 padding: prefix with 2-byte big-endian length, then
 *  pad to next multiple of 32 with zero bytes. The minimum padded
 *  length is 32 bytes (so plaintext up to 32 bytes gets exactly one
 *  block of padding). */
function pad(plaintext: Uint8Array): Uint8Array {
  if (plaintext.length === 0 || plaintext.length > NIP44_MAX_PLAINTEXT_BYTES) {
    throw new Error(
      `nip44-v2: plaintext length must be 1..${NIP44_MAX_PLAINTEXT_BYTES}, got ${plaintext.length}`,
    );
  }
  const unpadded = plaintext.length;
  const paddedLength = unpadded < 32 ? 32 : Math.ceil(unpadded / 32) * 32;
  const out = new Uint8Array(2 + paddedLength);
  out[0] = (unpadded >> 8) & 0xff;
  out[1] = unpadded & 0xff;
  plaintext.forEach((byte, i) => {
    out[2 + i] = byte;
  });
  return out;
}

/** Unpad — returns the original plaintext bytes. The padded shape is
 *  `length(2 bytes) || plaintext || zero_pad_to_32`, so the post-prefix
 *  tail is a multiple of 32; the total length is `2 + 32 * k` for
 *  some k >= 1. */
function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < 2 + 32) {
    throw new Error(`nip44-v2: padded length too short: ${padded.length}`);
  }
  if ((padded.length - 2) % 32 !== 0) {
    throw new Error(
      `nip44-v2: padded length after the 2-byte prefix must be a multiple of 32, got ${padded.length - 2}`,
    );
  }
  const unpaddedLength = (padded[0]! << 8) | padded[1]!;
  if (unpaddedLength < 1 || unpaddedLength > NIP44_MAX_PLAINTEXT_BYTES) {
    throw new Error(`nip44-v2: invalid plaintext length ${unpaddedLength}`);
  }
  if (2 + unpaddedLength > padded.length) {
    throw new Error("nip44-v2: padded buffer shorter than declared plaintext");
  }
  return padded.slice(2, 2 + unpaddedLength);
}

/** Compute NIP-44 v2 MAC: HMAC-SHA256(hmac_key, nonce || ciphertext || aad). */
function computeMac(
  hmacKey: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  return hmac(sha256, hmacKey, concatBytes(nonce, ciphertext, aad));
}

/** Concatenate several Uint8Arrays without copying intermediates
 *  beyond the final buffer. */
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** Constant-time comparison. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/** Encode a buffer as base64url (no padding). */
function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Decode a base64url string to bytes. */
function b64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/** Public inputs for the hybrid PQC NIP-44 v2 encryption. */
export interface Nip44PqcEncryptInput {
  /** 32-byte raw shared secret from secp256k1 ECDH (x-coordinate). */
  ecdhSharedSecret: Uint8Array;
  /** ML-KEM-768 encapsulated key (1088 bytes). */
  mlKemCiphertext: Uint8Array;
  /** 32-byte raw ML-KEM-768 shared secret (decapsulated). */
  mlKemSharedSecret: Uint8Array;
  /** Plaintext to encrypt (utf-8 string). */
  plaintext: string;
  /** Optional additional authenticated data (binds the message to a context). */
  aad?: Uint8Array;
}

/** Hybrid PQC NIP-44 v2 encryption. */
export function nip44PqcEncrypt(input: Nip44PqcEncryptInput): string {
  if (input.ecdhSharedSecret.length !== 32) {
    throw new Error("nip44PqcEncrypt: ecdhSharedSecret must be 32 bytes");
  }
  if (input.mlKemCiphertext.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
    throw new Error(
      `nip44PqcEncrypt: mlKemCiphertext must be ${ML_KEM_768_CIPHERTEXT_BYTES} bytes`,
    );
  }
  if (input.mlKemSharedSecret.length !== ML_KEM_768_SHARED_SECRET_BYTES) {
    throw new Error("nip44PqcEncrypt: mlKemSharedSecret must be 32 bytes");
  }
  // Concatenate the two shared secrets (upstream NIP-44 v2 uses one
  // shared secret; the PQC hybrid takes both).
  const sharedSecret = new Uint8Array(64);
  sharedSecret.set(input.ecdhSharedSecret, 0);
  sharedSecret.set(input.mlKemSharedSecret, 32);

  const conversationKey = deriveConversationKey(sharedSecret);
  const { chachaKey, chachaNonce, hmacKey } = deriveMessageKeys(conversationKey);
  const padded = pad(new TextEncoder().encode(input.plaintext));
  const ciphertext = chacha20(chachaKey, chachaNonce, padded);
  const mac = computeMac(hmacKey, chachaNonce, ciphertext, input.aad ?? new Uint8Array(0));
  return (
    PQC_NIP44_PREFIX +
    b64urlEncode(input.mlKemCiphertext) +
    "." +
    b64urlEncode(ciphertext) +
    "." +
    b64urlEncode(mac)
  );
}

/** Public inputs for the hybrid PQC NIP-44 v2 decryption. */
export interface Nip44PqcDecryptInput {
  /** 32-byte raw shared secret from secp256k1 ECDH. */
  ecdhSharedSecret: Uint8Array;
  /** 32-byte raw ML-KEM-768 shared secret (decapsulated from the envelope). */
  mlKemSharedSecret: Uint8Array;
  /** Envelope string (must start with `pqc2:`). */
  envelope: string;
  /** Optional additional authenticated data. */
  aad?: Uint8Array;
}

/** Hybrid PQC NIP-44 v2 decryption. Throws on auth failure or
 *  malformed envelope. */
export function nip44PqcDecrypt(input: Nip44PqcDecryptInput): string {
  if (!input.envelope.startsWith(PQC_NIP44_PREFIX)) {
    throw new Error(`nip44PqcDecrypt: envelope must start with "${PQC_NIP44_PREFIX}"`);
  }
  if (input.ecdhSharedSecret.length !== 32) {
    throw new Error("nip44PqcDecrypt: ecdhSharedSecret must be 32 bytes");
  }
  if (input.mlKemSharedSecret.length !== ML_KEM_768_SHARED_SECRET_BYTES) {
    throw new Error("nip44PqcDecrypt: mlKemSharedSecret must be 32 bytes");
  }
  const rest = input.envelope.slice(PQC_NIP44_PREFIX.length);
  const parts = rest.split(".");
  if (parts.length !== 3) {
    throw new Error(
      `nip44PqcDecrypt: envelope must have 3 dot-separated parts, got ${parts.length}`,
    );
  }
  const [kemB64, ctB64, macB64] = parts as [string, string, string];
  const kemCt = b64urlDecode(kemB64);
  const ciphertext = b64urlDecode(ctB64);
  const mac = b64urlDecode(macB64);
  if (kemCt.length !== ML_KEM_768_CIPHERTEXT_BYTES) {
    throw new Error(
      `nip44PqcDecrypt: mlKemCiphertext must be ${ML_KEM_768_CIPHERTEXT_BYTES} bytes, got ${kemCt.length}`,
    );
  }
  if (mac.length !== NIP44_MAC_BYTES) {
    throw new Error(`nip44PqcDecrypt: mac must be ${NIP44_MAC_BYTES} bytes, got ${mac.length}`);
  }
  const sharedSecret = new Uint8Array(64);
  sharedSecret.set(input.ecdhSharedSecret, 0);
  sharedSecret.set(input.mlKemSharedSecret, 32);
  const conversationKey = deriveConversationKey(sharedSecret);
  const { chachaKey, chachaNonce, hmacKey } = deriveMessageKeys(conversationKey);
  const expectedMac = computeMac(hmacKey, chachaNonce, ciphertext, input.aad ?? new Uint8Array(0));
  if (!constantTimeEqual(mac, expectedMac)) {
    throw new Error("nip44PqcDecrypt: MAC verification failed");
  }
  const padded = chacha20(chachaKey, chachaNonce, ciphertext);
  return new TextDecoder().decode(unpad(padded));
}

/** Detect whether a string is a PQC NIP-44 v2 envelope (whitepaper 1.1). */
export function isPqcNip44Envelope(value: string): boolean {
  return value.startsWith(PQC_NIP44_PREFIX);
}

/** Helper for the sender side: generate a fresh ML-KEM-768 keypair. */
export function generateMlKem768KeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const { publicKey, secretKey } = ml_kem768.keygen();
  return { publicKey, secretKey };
}

/** Helper for the sender side: encapsulate against a recipient's
 *  ML-KEM-768 public key. Returns the ciphertext and the shared
 *  secret to feed into `nip44PqcEncrypt`. */
export function encapsulateMlKem768(recipientPublicKey: Uint8Array): {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
} {
  const enc = ml_kem768.encapsulate(recipientPublicKey);
  return { ciphertext: enc.cipherText, sharedSecret: enc.sharedSecret };
}

/** Helper for the receiver side: decapsulate the ML-KEM-768 layer
 *  from the envelope. Returns the shared secret to feed into
 *  `nip44PqcDecrypt`. */
export function decapsulateMlKem768(
  recipientSecretKey: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return ml_kem768.decapsulate(ciphertext, recipientSecretKey);
}
