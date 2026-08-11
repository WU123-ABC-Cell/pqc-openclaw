// FIPS 204 ML-DSA-65 KAT invariants — vitest scaffold.
//
// These tests pin the contract of the mldsa65-key-storage module: key lengths,
// signature length, sign/verify round-trip, fingerprint stability, and
// tamper detection. They use the @noble/post-quantum-backed helpers that
// mldsa65-key-storage.ts owns (see that file for why we use @noble on Node 22).
// Each invariant asserts a property that must hold for any conformant ML-DSA-65
// implementation; the tests pass iff the production code honours FIPS 204 §4
// Table 1 parameter set 6.
import { describe, expect, it } from "vitest";
import {
  MLDSA65_MAX_MESSAGE_BYTES,
  MLDSA65_PUBLIC_KEY_LENGTH,
  MLDSA65_SECRET_KEY_LENGTH,
  MLDSA65_SIGNATURE_LENGTH,
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  generateMlDsa65KeyPair,
  isMlDsa65PublicKey,
  isMlDsa65SecretKey,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "./mldsa65-key-storage.js";

describe("ML-DSA-65 KAT (FIPS 204 §4, parameter set 6)", () => {
  it("public key is exactly 1952 raw bytes (FIPS 204 §4 Table 1)", () => {
    const kp = generateMlDsa65KeyPair();
    expect(kp.publicKey.length).toBe(MLDSA65_PUBLIC_KEY_LENGTH);
    expect(kp.publicKey.length).toBe(1952);
    // Round-trip through the prefixed string format the device store uses.
    const pem = encodeMlDsa65PublicKey(kp.publicKey);
    const raw = decodeMlDsa65PublicKey(pem);
    expect(raw.length).toBe(MLDSA65_PUBLIC_KEY_LENGTH);
  });

  it("secret key is exactly 4032 raw bytes (FIPS 204 §4 Table 1)", () => {
    const kp = generateMlDsa65KeyPair();
    expect(kp.secretKey.length).toBe(MLDSA65_SECRET_KEY_LENGTH);
    expect(kp.secretKey.length).toBe(4032);
    const pem = encodeMlDsa65SecretKey(kp.secretKey);
    const raw = decodeMlDsa65SecretKey(pem);
    expect(raw.length).toBe(MLDSA65_SECRET_KEY_LENGTH);
  });

  it("sign produces a 3309-byte signature (FIPS 204 §4 Table 1)", () => {
    const kp = generateMlDsa65KeyPair();
    const sig = signMlDsa65Payload(kp.secretKey, "hello pqc");
    const bytes = Buffer.from(sig, "base64url");
    expect(bytes.length).toBe(MLDSA65_SIGNATURE_LENGTH);
    expect(bytes.length).toBe(3309);
  });

  it("verify accepts a valid signature", () => {
    const kp = generateMlDsa65KeyPair();
    const publicPem = encodeMlDsa65PublicKey(kp.publicKey);
    const sig = signMlDsa65Payload(kp.secretKey, "hello pqc");
    expect(
      verifyMlDsa65Signature({
        publicKey: publicPem,
        payload: "hello pqc",
        signatureBase64Url: sig,
      }),
    ).toBe(true);
  });

  it("verify rejects a tampered signature", () => {
    const kp = generateMlDsa65KeyPair();
    const publicPem = encodeMlDsa65PublicKey(kp.publicKey);
    const sig = signMlDsa65Payload(kp.secretKey, "hello pqc");
    // Flip a bit in the middle of the signature.
    const sigBytes = Buffer.from(sig, "base64url");
    sigBytes[1500] ^= 0x01;
    const tampered = sigBytes.toString("base64url");
    expect(
      verifyMlDsa65Signature({
        publicKey: publicPem,
        payload: "hello pqc",
        signatureBase64Url: tampered,
      }),
    ).toBe(false);
  });

  it("verify rejects a wrong message", () => {
    const kp = generateMlDsa65KeyPair();
    const publicPem = encodeMlDsa65PublicKey(kp.publicKey);
    const sig = signMlDsa65Payload(kp.secretKey, "hello pqc");
    expect(
      verifyMlDsa65Signature({
        publicKey: publicPem,
        payload: "wrong message",
        signatureBase64Url: sig,
      }),
    ).toBe(false);
  });

  it("verify rejects a wrong public key", () => {
    const kp1 = generateMlDsa65KeyPair();
    const kp2 = generateMlDsa65KeyPair();
    const publicPem2 = encodeMlDsa65PublicKey(kp2.publicKey);
    const sig = signMlDsa65Payload(kp1.secretKey, "hello pqc");
    expect(
      verifyMlDsa65Signature({
        publicKey: publicPem2,
        payload: "hello pqc",
        signatureBase64Url: sig,
      }),
    ).toBe(false);
  });

  it("fingerprint is 64 lowercase hex chars (SHA-256)", () => {
    const kp = generateMlDsa65KeyPair();
    const fp = fingerprintMlDsa65PublicKey(kp.publicKey);
    expect(fp).toMatch(/^[a-f0-9]{64}$/);
  });

  it("fingerprint is stable across re-parse of the same key", () => {
    const kp = generateMlDsa65KeyPair();
    const pem = encodeMlDsa65PublicKey(kp.publicKey);
    const raw = decodeMlDsa65PublicKey(pem);
    const fp1 = fingerprintMlDsa65PublicKey(kp.publicKey);
    const fp2 = fingerprintMlDsa65PublicKey(raw);
    expect(fp1).toBe(fp2);
  });

  it("fingerprint is unique across independent keypairs", () => {
    const a = generateMlDsa65KeyPair();
    const b = generateMlDsa65KeyPair();
    expect(fingerprintMlDsa65PublicKey(a.publicKey)).not.toBe(
      fingerprintMlDsa65PublicKey(b.publicKey),
    );
  });

  it("isMlDsa65PublicKey accepts the prefixed format, rejects garbage", () => {
    const kp = generateMlDsa65KeyPair();
    const pem = encodeMlDsa65PublicKey(kp.publicKey);
    expect(isMlDsa65PublicKey(pem)).toBe(true);
    expect(isMlDsa65PublicKey("not a prefixed key")).toBe(false);
    expect(isMlDsa65PublicKey("")).toBe(false);
  });

  it("isMlDsa65SecretKey accepts the prefixed format, rejects garbage", () => {
    const kp = generateMlDsa65KeyPair();
    const pem = encodeMlDsa65SecretKey(kp.secretKey);
    expect(isMlDsa65SecretKey(pem)).toBe(true);
    expect(isMlDsa65SecretKey("not a prefixed key")).toBe(false);
    expect(isMlDsa65SecretKey("")).toBe(false);
  });

  it("rejects a mismatched public/secret key prefix (cross-label guards)", () => {
    const kp = generateMlDsa65KeyPair();
    const publicPem = encodeMlDsa65PublicKey(kp.publicKey);
    const secretPem = encodeMlDsa65SecretKey(kp.secretKey);
    expect(isMlDsa65PublicKey(secretPem)).toBe(false);
    expect(isMlDsa65SecretKey(publicPem)).toBe(false);
  });

  it("rejects an Ed25519 PEM disguised as ML-DSA-65", async () => {
    // Real Ed25519 SPKI from `crypto.generateKeyPairSync('ed25519')`. The ML-DSA-65
    // prefix guards must reject any PEM-bearing string so callers can't
    // accidentally downgrade to a classical algorithm at runtime.
    const { generateKeyPairSync } = await import("node:crypto");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const ed25519Pub = publicKey.export({ type: "spki", format: "pem" }) as string;
    const ed25519Priv = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    expect(isMlDsa65PublicKey(ed25519Pub)).toBe(false);
    expect(isMlDsa65SecretKey(ed25519Priv)).toBe(false);
  });

  it("oversized message is rejected with a clear error", () => {
    const kp = generateMlDsa65KeyPair();
    const big = "x".repeat(MLDSA65_MAX_MESSAGE_BYTES + 1);
    expect(() => signMlDsa65Payload(kp.secretKey, big)).toThrow(/exceeds/);
  });

  it("decode rejects malformed prefixed strings", () => {
    expect(() => decodeMlDsa65PublicKey("not prefixed at all")).toThrow();
    expect(() => decodeMlDsa65PublicKey("MLDSA65-SECRET-KEY:abc")).toThrow();
    expect(() => decodeMlDsa65SecretKey("not prefixed at all")).toThrow();
    expect(() => decodeMlDsa65SecretKey("MLDSA65-PUBLIC-KEY:abc")).toThrow();
  });

  it("encoded key round-trips through the prefixed format", () => {
    const kp = generateMlDsa65KeyPair();
    const publicPem = encodeMlDsa65PublicKey(kp.publicKey);
    const secretPem = encodeMlDsa65SecretKey(kp.secretKey);
    expect(Array.from(decodeMlDsa65PublicKey(publicPem))).toEqual(Array.from(kp.publicKey));
    expect(Array.from(decodeMlDsa65SecretKey(secretPem))).toEqual(Array.from(kp.secretKey));
  });
});
