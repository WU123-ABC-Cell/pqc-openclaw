// KAT scaffold for ML-DSA-65 (FIPS 204). The real, runnable suite lives in
// C:\Users\19929\Desktop\pqc-fork-scripts\run-kat.mjs (standalone Node, bypasses
// the WSL vitest hang). This file mirrors the same invariants as a vitest
// discoverable test, so the regular `pnpm test` lane also exercises ML-DSA-65.
import { describe, expect, it } from "vitest";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  generateMlDsa65KeyPair,
  MLDSA65_PUBLIC_KEY_LENGTH,
  MLDSA65_SECRET_KEY_LENGTH,
  MLDSA65_SIGNATURE_LENGTH,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "./mldsa65-key-storage.js";

describe("mldsa65-key-storage", () => {
  it("generates a keypair with the FIPS 204 §4 lengths", () => {
    const kp = generateMlDsa65KeyPair();
    expect(kp.publicKey.length).toBe(MLDSA65_PUBLIC_KEY_LENGTH);
    expect(kp.secretKey.length).toBe(MLDSA65_SECRET_KEY_LENGTH);
  });

  it("sign/verify round-trips with hedged signing", () => {
    const kp = generateMlDsa65KeyPair();
    const payload = "PQC-fork test payload — " + Date.now();
    const sig = signMlDsa65Payload(kp.secretKey, payload);
    const sigBytes = Buffer.from(sig, "base64url");
    expect(sigBytes.length).toBe(MLDSA65_SIGNATURE_LENGTH);
    expect(verifyMlDsa65Signature({ publicKey: kp.publicKey, payload, signatureBase64Url: sig })).toBe(true);
  });

  it("verify returns false when the message is tampered with", () => {
    const kp = generateMlDsa65KeyPair();
    const sig = signMlDsa65Payload(kp.secretKey, "original message");
    expect(
      verifyMlDsa65Signature({ publicKey: kp.publicKey, payload: "tampered message", signatureBase64Url: sig }),
    ).toBe(false);
  });

  it("encoded public/secret keys round-trip through base64url with stable prefixes", () => {
    const kp = generateMlDsa65KeyPair();
    const encPk = encodeMlDsa65PublicKey(kp.publicKey);
    const encSk = encodeMlDsa65SecretKey(kp.secretKey);
    expect(encPk.startsWith("MLDSA65-PUBLIC-KEY:")).toBe(true);
    expect(encSk.startsWith("MLDSA65-SECRET-KEY:")).toBe(true);
    expect(Buffer.from(decodeMlDsa65PublicKey(encPk))).toEqual(Buffer.from(kp.publicKey));
    expect(Buffer.from(decodeMlDsa65SecretKey(encSk))).toEqual(Buffer.from(kp.secretKey));
  });

  it("fingerprint of the public key is stable and 64 hex chars (SHA-256)", () => {
    const kp = generateMlDsa65KeyPair();
    const fp = fingerprintMlDsa65PublicKey(kp.publicKey);
    expect(fp).toMatch(/^[a-f0-9]{64}$/);
    expect(fp).toBe(fingerprintMlDsa65PublicKey(kp.publicKey));
  });
});
