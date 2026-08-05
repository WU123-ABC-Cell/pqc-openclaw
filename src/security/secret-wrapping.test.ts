import { describe, it, expect } from "vitest";
import {
  wrapSecret,
  unwrapSecret,
  serializeWrappedSecret,
  deserializeWrappedSecret,
  type WrappingKeyProvider,
} from "./secret-wrapping.js";

function makeProvider(keyBytes: Buffer, keyId = "test-key"): WrappingKeyProvider {
  return {
    getActiveKey: () => ({ key: keyBytes, keyId }),
    getKeyById: (id) => (id === keyId ? keyBytes : null),
  };
}

describe("secret-wrapping", () => {
  it("round-trips a PEM private key", () => {
    const key = Buffer.alloc(32, 1);
    const pem = "-----BEGIN PRIVATE KEY-----\nQUJDREVG\n-----END PRIVATE KEY-----\n";
    const provider = makeProvider(key);
    const wrapped = wrapSecret(Buffer.from(pem, "utf8"), provider);
    expect(wrapped.keyId).toBe("test-key");
    expect(wrapped.ciphertext).not.toContain("BEGIN");
    const recovered = unwrapSecret(wrapped, provider).toString("utf8");
    expect(recovered).toBe(pem);
  });

  it("round-trips a ML-DSA-65 PEM", () => {
    const key = Buffer.alloc(32, 2);
    const pem = "-----BEGIN PRIVATE KEY-----\nTUdTQQ==\n-----END PRIVATE KEY-----\n";
    const provider = makeProvider(key, "ml-dsa-key");
    const wrapped = wrapSecret(Buffer.from(pem, "utf8"), provider);
    expect(wrapped.keyId).toBe("ml-dsa-key");
    const recovered = unwrapSecret(wrapped, provider).toString("utf8");
    expect(recovered).toBe(pem);
  });

  it("produces different ciphertext for the same plaintext (random IV)", () => {
    const key = Buffer.alloc(32, 3);
    const pem = "-----BEGIN PRIVATE KEY-----\nU0FNRQ==\n-----END PRIVATE KEY-----\n";
    const provider = makeProvider(key);
    const a = wrapSecret(Buffer.from(pem, "utf8"), provider);
    const b = wrapSecret(Buffer.from(pem, "utf8"), provider);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.iv).not.toBe(b.iv);
    expect(unwrapSecret(a, provider).toString("utf8")).toBe(pem);
    expect(unwrapSecret(b, provider).toString("utf8")).toBe(pem);
  });

  it("fails to unwrap with a different key", () => {
    const keyA = Buffer.alloc(32, 4);
    const keyB = Buffer.alloc(32, 5);
    const providerA = makeProvider(keyA);
    const wrapped = wrapSecret(Buffer.from("secret data", "utf8"), providerA);
    const providerB = makeProvider(keyB);
    expect(() => unwrapSecret(wrapped, providerB)).toThrow();
  });

  it("fails to unwrap tampered ciphertext (auth tag check)", () => {
    const key = Buffer.alloc(32, 6);
    const provider = makeProvider(key);
    const wrapped = wrapSecret(Buffer.from("secret", "utf8"), provider);
    const tamperedBytes = Buffer.from(wrapped.ciphertext, "base64url");
    tamperedBytes[0] = tamperedBytes[0]! ^ 0x01;
    const tampered = { ...wrapped, ciphertext: tamperedBytes.toString("base64url") };
    expect(() => unwrapSecret(tampered, provider)).toThrow();
  });

  it("fails when keyId is unknown to the provider", () => {
    const key = Buffer.alloc(32, 7);
    const provider = makeProvider(key, "real-key");
    const wrapped = wrapSecret(Buffer.from("data", "utf8"), provider);
    const wrongProvider: WrappingKeyProvider = {
      getActiveKey: () => ({ key, keyId: "real-key" }),
      getKeyById: () => null,
    };
    expect(() => unwrapSecret(wrapped, wrongProvider)).toThrow();
  });

  it("serializes and deserializes WrappedSecret", () => {
    const key = Buffer.alloc(32, 8);
    const provider = makeProvider(key);
    const wrapped = wrapSecret(Buffer.from("serializable data", "utf8"), provider);
    const serialized = serializeWrappedSecret(wrapped);
    expect(typeof serialized).toBe("string");
    expect(serialized.length).toBeGreaterThan(0);
    const deserialized = deserializeWrappedSecret(serialized);
    expect(deserialized).toEqual(wrapped);
    expect(unwrapSecret(deserialized, provider).toString("utf8")).toBe("serializable data");
  });

  it("rejects invalid WrappedSecret payload", () => {
    expect(() => deserializeWrappedSecret("not-base64-url-or-garbage")).toThrow();
  });

  it("rejects non-32-byte wrapping keys", () => {
    const badKey = Buffer.alloc(16, 1);
    const provider = makeProvider(badKey);
    expect(() => wrapSecret(Buffer.from("x"), provider)).toThrow(/32 bytes/);
  });
});
