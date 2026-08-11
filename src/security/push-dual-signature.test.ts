// PQC fork M11: APNs ML-DSA-65 fallback signature (whitepaper 1.3).
//
// Apple APNs JWT auth is fixed to ES256 (P-256 ECDSA) per the Apple
// protocol and is not touched. M11 is the application-layer
// dual-signature envelope: each push payload carries BOTH an
// Ed25519 signature (for legacy clients) and an ML-DSA-65
// signature (for PQC clients). The client verifies both and
// rejects the payload if either fails.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  deriveCanonicalEd25519PrivateKeyRaw,
  deriveCanonicalEd25519PublicKeyRaw,
} from "../infra/ed25519-signature.js";
import {
  signPushPayloadDual,
  verifyPushPayloadDual,
} from "./push-dual-signature.js";

const tracked: Uint8Array[] = [];

function newEd25519KeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  // Same primitive path as the rest of the fork (device-identity
  // and ed25519-signature use node:crypto Ed25519 keys, not @noble).
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const publicKeyRaw = deriveCanonicalEd25519PublicKeyRaw(publicKeyPem);
  const privateKeyRaw = deriveCanonicalEd25519PrivateKeyRaw(privateKeyPem);
  tracked.push(publicKeyRaw, privateKeyRaw);
  return { publicKey: publicKeyRaw, secretKey: privateKeyRaw };
}

function newMlDsa65KeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const { secretKey, publicKey } = ml_dsa65.keygen(randomBytes(32));
  tracked.push(secretKey, publicKey);
  return { publicKey, secretKey };
}

beforeEach(() => {
  while (tracked.length > 0) tracked.pop();
});

afterEach(() => {
  while (tracked.length > 0) tracked.pop();
});

describe("signPushPayloadDual + verifyPushPayloadDual (whitepaper 1.3)", () => {
  it("round-trips a small JSON payload through the dual-signature envelope", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const payload = { alert: "you have a new message", conversationId: "abc-123" };
    const signed = signPushPayloadDual({
      payload,
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed25519-key-2026-08",
      keyIdMldsa65: "mldsa65-key-2026-08",
    });
    expect(signed.envelope.algorithms).toEqual(["ed25519", "ml-dsa-65"]);
    expect(signed.envelope.key_id_ed25519).toBe("ed25519-key-2026-08");
    expect(signed.envelope.key_id_mldsa65).toBe("mldsa65-key-2026-08");
    // The Ed25519 sig is 64 bytes; the ML-DSA-65 sig is 3309 bytes.
    // The base64url encoding length is a sanity check.
    expect(signed.envelope.ed25519_sig.length).toBe(86);
    expect(signed.envelope.mldsa65_sig.length).toBe(4412);

    verifyPushPayloadDual({
      payload: signed.payload,
      ed25519PublicKey: ed.publicKey,
      mldsa65PublicKey: ml.publicKey,
      envelope: signed.envelope,
    });
  });

  it("fails closed on a tampered Ed25519 signature", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "x" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    const tamperedSig = Buffer.from(signed.envelope.ed25519_sig, "base64url");
    tamperedSig[0] ^= 0x80;
    const tampered = { ...signed.envelope, ed25519_sig: Buffer.from(tamperedSig).toString("base64url") };
    expect(() =>
      verifyPushPayloadDual({
        payload: signed.payload,
        ed25519PublicKey: ed.publicKey,
        mldsa65PublicKey: ml.publicKey,
        envelope: tampered,
      }),
    ).toThrow(/Ed25519 signature failed/);
  });

  it("fails closed on a tampered ML-DSA-65 signature", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "x" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    const tamperedSig = Buffer.from(signed.envelope.mldsa65_sig, "base64url");
    tamperedSig[10] ^= 0x01;
    const tampered = { ...signed.envelope, mldsa65_sig: Buffer.from(tamperedSig).toString("base64url") };
    expect(() =>
      verifyPushPayloadDual({
        payload: signed.payload,
        ed25519PublicKey: ed.publicKey,
        mldsa65PublicKey: ml.publicKey,
        envelope: tampered,
      }),
    ).toThrow(/ML-DSA-65 signature failed/);
  });

  it("fails closed when the payload bytes are tampered after signing", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "the original message" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    // Mutate one byte of the payload bytes. Both signatures must
    // catch the change.
    const tamperedPayload = new Uint8Array(signed.payload);
    tamperedPayload[5] ^= 0x01;
    expect(() =>
      verifyPushPayloadDual({
        payload: tamperedPayload,
        ed25519PublicKey: ed.publicKey,
        mldsa65PublicKey: ml.publicKey,
        envelope: signed.envelope,
      }),
    ).toThrow(/Ed25519 signature failed/);
  });

  it("fails closed when the wrong Ed25519 public key is supplied", () => {
    const ed = newEd25519KeyPair();
    const wrongEd = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "x" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    expect(() =>
      verifyPushPayloadDual({
        payload: signed.payload,
        ed25519PublicKey: wrongEd.publicKey,
        mldsa65PublicKey: ml.publicKey,
        envelope: signed.envelope,
      }),
    ).toThrow(/Ed25519 signature failed/);
  });

  it("fails closed when the wrong ML-DSA-65 public key is supplied", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const wrongMl = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "x" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    expect(() =>
      verifyPushPayloadDual({
        payload: signed.payload,
        ed25519PublicKey: ed.publicKey,
        mldsa65PublicKey: wrongMl.publicKey,
        envelope: signed.envelope,
      }),
    ).toThrow(/ML-DSA-65 signature failed/);
  });

  it("rejects a wrong-size Ed25519 secret key", () => {
    const ml = newMlDsa65KeyPair();
    expect(() =>
      signPushPayloadDual({
        payload: { alert: "x" },
        ed25519SecretKey: new Uint8Array(16),
        mldsa65SecretKey: ml.secretKey,
        keyIdEd25519: "ed",
        keyIdMldsa65: "ml",
      }),
    ).toThrow(/32 bytes/);
  });

  it("rejects a wrong-size ML-DSA-65 secret key", () => {
    const ed = newEd25519KeyPair();
    expect(() =>
      signPushPayloadDual({
        payload: { alert: "x" },
        ed25519SecretKey: ed.secretKey,
        mldsa65SecretKey: new Uint8Array(1952),
        keyIdEd25519: "ed",
        keyIdMldsa65: "ml",
      }),
    ).toThrow(/4032 bytes/);
  });

  it("rejects an empty keyId hint", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    expect(() =>
      signPushPayloadDual({
        payload: { alert: "x" },
        ed25519SecretKey: ed.secretKey,
        mldsa65SecretKey: ml.secretKey,
        keyIdEd25519: "",
        keyIdMldsa65: "ml",
      }),
    ).toThrow(/non-empty/);
  });

  it("rejects an envelope with a non-allowed algorithms header", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "x" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    const tampered = { ...signed.envelope, algorithms: ["ed25519"] as unknown as ["ed25519", "ml-dsa-65"] };
    expect(() =>
      verifyPushPayloadDual({
        payload: signed.payload,
        ed25519PublicKey: ed.publicKey,
        mldsa65PublicKey: ml.publicKey,
        envelope: tampered,
      }),
    ).toThrow(/unexpected algorithms/);
  });

  it("rejects an envelope with a wrong-length Ed25519 sig", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "x" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    const tampered = { ...signed.envelope, ed25519_sig: "AAAA" };
    expect(() =>
      verifyPushPayloadDual({
        payload: signed.payload,
        ed25519PublicKey: ed.publicKey,
        mldsa65PublicKey: ml.publicKey,
        envelope: tampered,
      }),
    ).toThrow(/64 bytes/);
  });

  it("rejects an envelope with a wrong-length ML-DSA-65 sig", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const signed = signPushPayloadDual({
      payload: { alert: "x" },
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    const tampered = { ...signed.envelope, mldsa65_sig: "AAAA" };
    expect(() =>
      verifyPushPayloadDual({
        payload: signed.payload,
        ed25519PublicKey: ed.publicKey,
        mldsa65PublicKey: ml.publicKey,
        envelope: tampered,
      }),
    ).toThrow(/3309 bytes/);
  });

  it("canonicalises the payload via JSON.stringify before signing", () => {
    const ed = newEd25519KeyPair();
    const ml = newMlDsa65KeyPair();
    const payload = { b: 2, a: 1, c: [3, 4] };
    const signed = signPushPayloadDual({
      payload,
      ed25519SecretKey: ed.secretKey,
      mldsa65SecretKey: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
    });
    // The payload bytes are exactly the JSON.stringify output
    // (no canonicalisation beyond what JSON.stringify gives us).
    expect(new TextDecoder().decode(signed.payload)).toBe(JSON.stringify(payload));
    verifyPushPayloadDual({
      payload: signed.payload,
      ed25519PublicKey: ed.publicKey,
      mldsa65PublicKey: ml.publicKey,
      envelope: signed.envelope,
    });
  });
});
