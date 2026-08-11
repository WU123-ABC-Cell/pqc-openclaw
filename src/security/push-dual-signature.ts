// Push-notification payload dual signature (PQC whitepaper 1.3).
//
// Apple APNs JWT auth is fixed to ES256 (P-256 ECDSA) per Apple's
// protocol and is not touched by this fork. The "dual signature"
// upgrade is at the application layer: each push payload carries
// two signatures — one Ed25519 (for legacy clients) and one
// ML-DSA-65 (for PQC clients). The client verifies both and
// rejects the payload if either fails.
//
// Wire format — the payload itself is JSON; the signature envelope
// is a sibling JSON object with the same canonicalised bytes:
//
//   payload     : { ... }                 (UTF-8 JSON, no trailing newline)
//   envelope    : {
//                   algs: ["ed25519", "ml-dsa-65"],
//                   ed25519_sig: <base64url 64-byte sig>,
//                   mldsa65_sig: <base64url 3309-byte sig>,
//                   key_id_ed25519: <id hint for the operator>,
//                   key_id_mldsa65: <id hint for the operator>
//                 }
//
// The client identifies the signing keys by the key_id hints; the
// actual public keys are out-of-band (the operator publishes them
// through the device-identity bootstrap path, the same one that
// already carries the ML-DSA-65 public key today).
//
// Ed25519 here reuses `src/infra/ed25519-signature.ts` so the
// payload signing path stays on the same primitives as the rest
// of the fork (device identity, dual device sign). ML-DSA-65 is
// via @noble/post-quantum (FIPS 204). The public input shape
// stays in raw bytes (32-byte Ed25519 secret, 4032-byte ML-DSA-65
// secret) — same as the device-identity module.
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import {
  ed25519PrivateKeyPemFromRaw,
  ed25519PublicKeyPemFromRaw,
  signEd25519Payload,
  verifyEd25519SignatureBytes,
} from "../infra/ed25519-signature.js";

/** Canonical JSON serialisation: utf-8 bytes of `JSON.stringify(value)`. */
function canonicalJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

/** Encode a buffer as base64url (no padding). */
function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Decode a base64url string to bytes. */
function b64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/** Public input for `signPushPayloadDual`. */
export interface PushDualSignInput {
  /** Plain JSON payload. Will be canonicalised via `JSON.stringify`. */
  payload: unknown;
  /** 32-byte Ed25519 secret key (raw, the same shape the Ed25519
   *  helper module uses for device signing). */
  ed25519SecretKey: Uint8Array;
  /** 4032-byte ML-DSA-65 secret key (raw, the same shape the
   *  `mldsa65-key-storage` module uses for device signing). */
  mldsa65SecretKey: Uint8Array;
  /** Operator hint for the Ed25519 key. Stored verbatim in the
   *  envelope; the client uses it to look up the corresponding
   *  public key. */
  keyIdEd25519: string;
  /** Operator hint for the ML-DSA-65 key. */
  keyIdMldsa65: string;
}

/** The dual-signature envelope. */
export interface PushDualSignature {
  algorithms: ["ed25519", "ml-dsa-65"];
  ed25519_sig: string;
  mldsa65_sig: string;
  key_id_ed25519: string;
  key_id_mldsa65: string;
}

/** Sign a push payload with both Ed25519 and ML-DSA-65. */
export function signPushPayloadDual(input: PushDualSignInput): {
  payload: Uint8Array;
  envelope: PushDualSignature;
} {
  if (input.ed25519SecretKey.length !== 32) {
    throw new Error(
      `signPushPayloadDual: ed25519SecretKey must be 32 bytes, got ${input.ed25519SecretKey.length}`,
    );
  }
  if (input.mldsa65SecretKey.length !== 4032) {
    throw new Error(
      `signPushPayloadDual: mldsa65SecretKey must be 4032 bytes, got ${input.mldsa65SecretKey.length}`,
    );
  }
  if (input.keyIdEd25519.length === 0 || input.keyIdMldsa65.length === 0) {
    throw new Error("signPushPayloadDual: keyIdEd25519 and keyIdMldsa65 must be non-empty");
  }
  const payload = canonicalJson(input.payload);

  // Ed25519 via node:crypto through the ed25519-signature helper.
  // The helper accepts a PKCS8 PEM, so we round-trip the raw 32-byte
  // secret through the canonical PEM envelope the rest of the fork
  // already uses. Payload bytes are passed through as UTF-8 — the
  // existing signEd25519Payload path is the one the device-identity
  // module uses, so dual-signed pushes interop with the same byte
  // string as dual-signed device payloads.
  const ed25519SecretPem = ed25519PrivateKeyPemFromRaw(Buffer.from(input.ed25519SecretKey));
  const ed25519SigB64Url = signEd25519Payload(ed25519SecretPem, Buffer.from(payload).toString("utf8"));
  const ed25519Sig = new Uint8Array(Buffer.from(ed25519SigB64Url, "base64url"));

  // ML-DSA-65 via @noble/post-quantum (FIPS 204).
  const mldsa65Sig = ml_dsa65.sign(payload, input.mldsa65SecretKey);

  return {
    payload,
    envelope: {
      algorithms: ["ed25519", "ml-dsa-65"],
      ed25519_sig: b64urlEncode(ed25519Sig),
      mldsa65_sig: b64urlEncode(mldsa65Sig),
      key_id_ed25519: input.keyIdEd25519,
      key_id_mldsa65: input.keyIdMldsa65,
    },
  };
}

/** Public input for `verifyPushPayloadDual`. */
export interface PushDualVerifyInput {
  /** Canonical payload bytes (the exact bytes that were signed). */
  payload: Uint8Array;
  /** 32-byte Ed25519 public key. */
  ed25519PublicKey: Uint8Array;
  /** 1952-byte ML-DSA-65 public key. */
  mldsa65PublicKey: Uint8Array;
  /** The envelope returned by the sender. */
  envelope: PushDualSignature;
}

/** Verify a push payload's dual signature. Throws on the first
 *  failed algorithm; the client MUST NOT accept the payload if
 *  either fails. */
export function verifyPushPayloadDual(input: PushDualVerifyInput): void {
  if (input.ed25519PublicKey.length !== 32) {
    throw new Error(
      `verifyPushPayloadDual: ed25519PublicKey must be 32 bytes, got ${input.ed25519PublicKey.length}`,
    );
  }
  if (input.mldsa65PublicKey.length !== 1952) {
    throw new Error(
      `verifyPushPayloadDual: mldsa65PublicKey must be 1952 bytes, got ${input.mldsa65PublicKey.length}`,
    );
  }
  // Algorithm header guard: the envelope MUST advertise exactly
  // the two algorithms we expect. A future migration to drop
  // Ed25519 (or add a third algorithm) is a wire-format change
  // and the verifier enforces it.
  if (
    input.envelope.algorithms.length !== 2 ||
    input.envelope.algorithms[0] !== "ed25519" ||
    input.envelope.algorithms[1] !== "ml-dsa-65"
  ) {
    throw new Error(
      `verifyPushPayloadDual: unexpected algorithms ${JSON.stringify(input.envelope.algorithms)}`,
    );
  }
  const ed25519Sig = b64urlDecode(input.envelope.ed25519_sig);
  if (ed25519Sig.length !== 64) {
    throw new Error(
      `verifyPushPayloadDual: ed25519_sig must be 64 bytes, got ${ed25519Sig.length}`,
    );
  }
  // Ed25519 verify via node:crypto through the ed25519-signature
  // helper. The helper accepts a SPKI PEM and a base64url-encoded
  // signature, so we wrap the raw 32-byte public key once and pass
  // the payload as raw bytes (the helper accepts Buffer).
  const ed25519PublicPem = ed25519PublicKeyPemFromRaw(Buffer.from(input.ed25519PublicKey));
  const ed25519Ok = verifyEd25519SignatureBytes({
    publicKey: ed25519PublicPem,
    payload: Buffer.from(input.payload),
    signatureBase64Url: input.envelope.ed25519_sig,
  });
  if (!ed25519Ok) {
    throw new Error("verifyPushPayloadDual: Ed25519 signature failed");
  }
  const mldsa65Sig = b64urlDecode(input.envelope.mldsa65_sig);
  if (mldsa65Sig.length !== 3309) {
    throw new Error(
      `verifyPushPayloadDual: mldsa65_sig must be 3309 bytes, got ${mldsa65Sig.length}`,
    );
  }
  if (!ml_dsa65.verify(mldsa65Sig, input.payload, input.mldsa65PublicKey)) {
    throw new Error("verifyPushPayloadDual: ML-DSA-65 signature failed");
  }
}
