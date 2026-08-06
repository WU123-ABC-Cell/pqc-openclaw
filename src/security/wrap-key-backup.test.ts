// PQC step 2.3.5.D: unit tests for wrap-key backup/restore.
import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
  deserializeBackup,
  exportWrapKey,
  importWrapKey,
  serializeBackup,
  WrapKeyBackupError,
  type ExportedWrapKey,
} from "./wrap-key-backup.js";

const KEY_BYTES = 32;

function makeKey(seed = 0x42): Buffer {
  const buf = Buffer.alloc(KEY_BYTES, seed);
  return buf;
}

describe("exportWrapKey + importWrapKey round-trip", () => {
  it("returns the same key with the right passphrase", () => {
    const key = makeKey();
    const blob = exportWrapKey(key, "openclaw-wrap-test", { passphrase: "correct horse battery staple" });
    const { key: recovered, keyId } = importWrapKey(blob, { passphrase: "correct horse battery staple" });
    expect(recovered.equals(key)).toBe(true);
    expect(keyId).toBe("openclaw-wrap-test");
  });

  it("produces a self-describing blob with version 1", () => {
    const blob = exportWrapKey(makeKey(), "kid", { passphrase: "pw" });
    expect(blob.version).toBe(1);
    expect(blob.algorithm).toBe("aes-256-gcm");
    expect(blob.kdf).toBe("pbkdf2-sha256");
    expect(blob.iterations).toBe(600_000);
    expect(blob.keyId).toBe("kid");
    expect(blob.salt.length).toBeGreaterThan(0);
    expect(blob.iv.length).toBeGreaterThan(0);
    expect(blob.ciphertext.length).toBeGreaterThan(0);
    expect(blob.authTag.length).toBeGreaterThan(0);
  });

  it("uses a fresh random salt and IV each call", () => {
    const key = makeKey();
    const a = exportWrapKey(key, "kid", { passphrase: "pw" });
    const b = exportWrapKey(key, "kid", { passphrase: "pw" });
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.authTag).not.toBe(b.authTag);
  });

  it("respects a custom iteration count", () => {
    const key = makeKey();
    const blob = exportWrapKey(key, "kid", { passphrase: "pw", iterations: 10_000 });
    expect(blob.iterations).toBe(10_000);
    const { key: recovered } = importWrapKey(blob, { passphrase: "pw" });
    expect(recovered.equals(key)).toBe(true);
  });
});

describe("importWrapKey error handling", () => {
  const validBlob = exportWrapKey(makeKey(), "kid", { passphrase: "right" });

  it("rejects the wrong passphrase", () => {
    expect(() => importWrapKey(validBlob, { passphrase: "wrong" })).toThrow(WrapKeyBackupError);
  });

  it("rejects an empty passphrase", () => {
    expect(() => importWrapKey(validBlob, { passphrase: "" })).toThrow(/passphrase/);
  });

  it("rejects a blob with the wrong version", () => {
    const tampered: ExportedWrapKey = { ...validBlob, version: 99 };
    expect(() => importWrapKey(tampered, { passphrase: "right" })).toThrow(/version/);
  });

  it("rejects a blob with the wrong algorithm", () => {
    const tampered: ExportedWrapKey = { ...validBlob, algorithm: "chacha20-poly1305" as "aes-256-gcm" };
    expect(() => importWrapKey(tampered, { passphrase: "right" })).toThrow(/algorithm/);
  });

  it("rejects a blob with the wrong kdf", () => {
    const tampered: ExportedWrapKey = { ...validBlob, kdf: "scrypt" as "pbkdf2-sha256" };
    expect(() => importWrapKey(tampered, { passphrase: "right" })).toThrow(/kdf/);
  });

  it("rejects iterations out of bounds", () => {
    const tooLow: ExportedWrapKey = { ...validBlob, iterations: 100 };
    expect(() => importWrapKey(tooLow, { passphrase: "right" })).toThrow(/iterations/);
    const tooHigh: ExportedWrapKey = { ...validBlob, iterations: 100_000_000 };
    expect(() => importWrapKey(tooHigh, { passphrase: "right" })).toThrow(/iterations/);
  });

  it("rejects a blob with tampered ciphertext (auth tag mismatch)", () => {
    const tampered: ExportedWrapKey = {
      ...validBlob,
      ciphertext: "A" + validBlob.ciphertext.slice(1),
    };
    expect(() => importWrapKey(tampered, { passphrase: "right" })).toThrow(/decryption failed/);
  });

  it("rejects a blob with tampered authTag", () => {
    const tampered: ExportedWrapKey = {
      ...validBlob,
      authTag: "A" + validBlob.authTag.slice(1),
    };
    expect(() => importWrapKey(tampered, { passphrase: "right" })).toThrow(/decryption failed/);
  });

  it("rejects a blob with tampered salt", () => {
    const tampered: ExportedWrapKey = {
      ...validBlob,
      salt: "A" + validBlob.salt.slice(1),
    };
    expect(() => importWrapKey(tampered, { passphrase: "right" })).toThrow(/decryption failed/);
  });
});

describe("exportWrapKey input validation", () => {
  it("rejects a key that is not 32 bytes", () => {
    expect(() => exportWrapKey(Buffer.alloc(31), "kid", { passphrase: "pw" })).toThrow(/32 bytes/);
    expect(() => exportWrapKey(Buffer.alloc(33), "kid", { passphrase: "pw" })).toThrow(/32 bytes/);
  });

  it("rejects an empty passphrase", () => {
    expect(() => exportWrapKey(makeKey(), "kid", { passphrase: "" })).toThrow(/passphrase/);
  });
});

describe("serializeBackup + deserializeBackup", () => {
  it("round-trips a blob through a base64url string", () => {
    const key = makeKey();
    const original = exportWrapKey(key, "kid", { passphrase: "pw" });
    const serialized = serializeBackup(original);
    const recovered = deserializeBackup(serialized);
    expect(recovered).toEqual(original);
    const { key: recoveredKey } = importWrapKey(recovered, { passphrase: "pw" });
    expect(recoveredKey.equals(key)).toBe(true);
  });

  it("rejects garbage that is not base64url JSON", () => {
    expect(() => deserializeBackup("not-valid-base64!@#$%^&*()")).toThrow(WrapKeyBackupError);
  });

  it("rejects valid base64url but non-JSON content", () => {
    const nonJson = Buffer.from("hello world", "utf8").toString("base64url");
    expect(() => deserializeBackup(nonJson)).toThrow(/not base64url JSON/);
  });

  it("rejects valid JSON that is not an object", () => {
    const arr = Buffer.from(JSON.stringify([1, 2, 3]), "utf8").toString("base64url");
    expect(() => deserializeBackup(arr)).toThrow(/not an object/);
  });
});

describe("WrapKeyBackupError", () => {
  it("has the correct name and is an Error", () => {
    const err = new WrapKeyBackupError("test");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("WrapKeyBackupError");
    expect(err.message).toBe("test");
  });
});
