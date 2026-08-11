// FIPS 204 ML-DSA-65 KAT invariants — vitest scaffold.
//
// These tests pin the contract of the mldsa65-key-storage module: key lengths,
// signature length, sign/verify round-trip, fingerprint stability, and
// tamper detection. They use Node 22+ native `crypto.generateKeyPairSync("ml-dsa-65")`
// (no external dep). Each invariant asserts a property that must hold for any
// conformant ML-DSA-65 implementation; the tests pass iff the production code
// honours FIPS 204 §4 Table 1 parameter set 6.
import { describe, expect, it } from "vitest";
import {
  MLDSA65_PUBLIC_KEY_LENGTH,
  MLDSA65_SECRET_KEY_LENGTH,
  MLDSA65_SIGNATURE_LENGTH,
  MLDSA65_MAX_MESSAGE_BYTES,
  extractRawMlDsa65PublicKey,
  extractRawMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  generateMlDsa65KeyPair,
  isMlDsa65PrivateKeyPem,
  isMlDsa65PublicKeyPem,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "./mldsa65-key-storage.js";

describe("ML-DSA-65 KAT (FIPS 204 §4, parameter set 6)", () => {
  it("public key is exactly 1952 raw bytes (FIPS 204 §4 Table 1)", () => {
    const kp = generateMlDsa65KeyPair();
    const raw = extractRawMlDsa65PublicKey(kp.publicKeyPem);
    expect(raw.length).toBe(MLDSA65_PUBLIC_KEY_LENGTH);
    expect(raw.length).toBe(1952);
  });

  it("secret key is exactly 4032 raw bytes (FIPS 204 §4 Table 1)", () => {
    const kp = generateMlDsa65KeyPair();
    const raw = extractRawMlDsa65SecretKey(kp.privateKeyPem);
    expect(raw.length).toBe(MLDSA65_SECRET_KEY_LENGTH);
    expect(raw.length).toBe(4032);
  });

  it("sign produces a 3309-byte signature (FIPS 204 §4 Table 1)", () => {
    const kp = generateMlDsa65KeyPair();
    const sig = signMlDsa65Payload(kp.privateKeyPem, "hello pqc");
    const bytes = Buffer.from(sig, "base64url");
    expect(bytes.length).toBe(MLDSA65_SIGNATURE_LENGTH);
    expect(bytes.length).toBe(3309);
  });

  it("verify accepts a valid signature", () => {
    const kp = generateMlDsa65KeyPair();
    const sig = signMlDsa65Payload(kp.privateKeyPem, "hello pqc");
    expect(
      verifyMlDsa65Signature({
        publicKeyPem: kp.publicKeyPem,
        payload: "hello pqc",
        signatureBase64Url: sig,
      }),
    ).toBe(true);
  });

  it("verify rejects a tampered signature", () => {
    const kp = generateMlDsa65KeyPair();
    const sig = signMlDsa65Payload(kp.privateKeyPem, "hello pqc");
    // Flip a bit in the middle of the signature.
    const sigBytes = Buffer.from(sig, "base64url");
    sigBytes[1500] ^= 0x01;
    const tampered = sigBytes.toString("base64url");
    expect(
      verifyMlDsa65Signature({
        publicKeyPem: kp.publicKeyPem,
        payload: "hello pqc",
        signatureBase64Url: tampered,
      }),
    ).toBe(false);
  });

  it("verify rejects a wrong message", () => {
    const kp = generateMlDsa65KeyPair();
    const sig = signMlDsa65Payload(kp.privateKeyPem, "hello pqc");
    expect(
      verifyMlDsa65Signature({
        publicKeyPem: kp.publicKeyPem,
        payload: "wrong message",
        signatureBase64Url: sig,
      }),
    ).toBe(false);
  });

  it("verify rejects a wrong public key", () => {
    const kp1 = generateMlDsa65KeyPair();
    const kp2 = generateMlDsa65KeyPair();
    const sig = signMlDsa65Payload(kp1.privateKeyPem, "hello pqc");
    expect(
      verifyMlDsa65Signature({
        publicKeyPem: kp2.publicKeyPem,
        payload: "hello pqc",
        signatureBase64Url: sig,
      }),
    ).toBe(false);
  });

  it("fingerprint is 64 lowercase hex chars (SHA-256)", () => {
    const kp = generateMlDsa65KeyPair();
    const fp = fingerprintMlDsa65PublicKey(kp.publicKeyPem);
    expect(fp).toMatch(/^[a-f0-9]{64}$/);
  });

  it("fingerprint is stable across re-parse of the same PEM", () => {
    const kp = generateMlDsa65KeyPair();
    const fp1 = fingerprintMlDsa65PublicKey(kp.publicKeyPem);
    const fp2 = fingerprintMlDsa65PublicKey(kp.publicKeyPem);
    expect(fp1).toBe(fp2);
  });

  it("fingerprint is unique across independent keypairs", () => {
    const a = generateMlDsa65KeyPair();
    const b = generateMlDsa65KeyPair();
    expect(fingerprintMlDsa65PublicKey(a.publicKeyPem)).not.toBe(
      fingerprintMlDsa65PublicKey(b.publicKeyPem),
    );
  });

  it("isMlDsa65PublicKeyPem accepts valid SPKI PEM, rejects garbage", () => {
    const kp = generateMlDsa65KeyPair();
    expect(isMlDsa65PublicKeyPem(kp.publicKeyPem)).toBe(true);
    expect(isMlDsa65PublicKeyPem("not a pem")).toBe(false);
    expect(isMlDsa65PublicKeyPem("")).toBe(false);
  });

  it("isMlDsa65PrivateKeyPem accepts valid PKCS8 PEM, rejects garbage", () => {
    const kp = generateMlDsa65KeyPair();
    expect(isMlDsa65PrivateKeyPem(kp.privateKeyPem)).toBe(true);
    expect(isMlDsa65PrivateKeyPem("not a pem")).toBe(false);
  });

  it("rejects the deprecated MLDSA65-PUBLIC-KEY: base64url format", () => {
    expect(() =>
      isMlDsa65PublicKeyPem("MLDSA65-PUBLIC-KEY:6JVi4pXommwNfKvK3Ddedr"),
    ).toThrow(/deprecated/);
    expect(() =>
      isMlDsa65PrivateKeyPem("MLDSA65-SECRET-KEY:6JVi4pXommwNfKvK3Ddedr"),
    ).toThrow(/deprecated/);
  });

  it("rejects an Ed25519 PEM disguised as ML-DSA-65", () => {
    // Real Ed25519 SPKI from `crypto.generateKeyPairSync('ed25519')`.
    const { publicKey, privateKey } = (await import("node:crypto")).generateKeyPairSync(
      "ed25519",
    );
    const ed25519Pub = publicKey.export({ type: "spki", format: "pem" }) as string;
    const ed25519Priv = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    expect(isMlDsa65PublicKeyPem(ed25519Pub)).toBe(false);
    expect(isMlDsa65PrivateKeyPem(ed25519Priv)).toBe(false);
  });

  it("oversized message is rejected with a clear error", () => {
    const kp = generateMlDsa65KeyPair();
    const big = "x".repeat(MLDSA65_MAX_MESSAGE_BYTES + 1);
    expect(() => signMlDsa65Payload(kp.privateKeyPem, big)).toThrow(/exceeds/);
  });
});
