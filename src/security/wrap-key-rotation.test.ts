// PQC fork M7: wrap-key rotation + backup / restore.
//   2.2.5.C — rotation re-wraps the same ML-DSA-65 plaintext under a
//             new key and updates keyId + BLOB.
//   2.2.5.D — backup encrypts the 32-byte key under a passphrase
//             (PBKDF2-SHA256 + AES-256-GCM). Restore is the inverse
//             and refuses the wrong passphrase.
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { encodeMlDsa65SecretKey } from "../infra/mldsa65-key-storage.js";
import {
  deserializeWrappedSecret,
  type WrappingKeyProvider,
  type ActiveWrappingKey,
  serializeWrappedSecret,
  unwrapSecret,
  wrapSecret,
} from "./secret-wrapping.js";
import {
  constantTimeEqual,
  exportWrapKey,
  importWrapKey,
  rotateWrappingKey,
  WRAP_KEY_BACKUP_CONSTANTS,
} from "./wrap-key-rotation.js";

class InMemoryKeyring implements WrappingKeyProvider {
  private activeId: string;
  private readonly keys = new Map<string, Buffer>();

  constructor(activeId: string) {
    this.activeId = activeId;
  }

  addKey(keyId: string, key: Buffer): void {
    this.keys.set(keyId, Buffer.from(key));
  }

  drop(keyId: string): void {
    this.keys.delete(keyId);
  }

  getActiveKey(): ActiveWrappingKey {
    const key = this.keys.get(this.activeId);
    if (!key) {
      throw new Error(`InMemoryKeyring: active key missing: ${this.activeId}`);
    }
    return { key, keyId: this.activeId };
  }

  getKeyById(keyId: string): Buffer | null {
    const key = this.keys.get(keyId);
    return key ? Buffer.from(key) : null;
  }
}

const trackedKeys: Buffer[] = [];
function newKey(): Buffer {
  const k = randomBytes(32);
  trackedKeys.push(k);
  return k;
}

beforeEach(() => {
  while (trackedKeys.length > 0) trackedKeys.pop();
});

afterEach(() => {
  while (trackedKeys.length > 0) {
    trackedKeys.pop()?.fill(0);
  }
});

describe("rotateWrappingKey (whitepaper 2.2.5.C)", () => {
  it("re-wraps the same plaintext under the new key", () => {
    const oldKey = newKey();
    const newKeyBuf = newKey();
    const oldRing = new InMemoryKeyring("wrap-key-2026-08");
    oldRing.addKey("wrap-key-2026-08", oldKey);
    const newRing = new InMemoryKeyring("wrap-key-2026-09");
    newRing.addKey("wrap-key-2026-09", newKeyBuf);

    // Build a stored identity with a wrap envelope (as M5 produces).
    const secret = randomBytes(4032);
    const wrapped = wrapSecret(Buffer.from(secret), oldRing);
    const stored = {
      privateKeyPem: encodeMlDsa65SecretKey(secret),
      mldsaPrivateKeyWrapped: serializeWrappedSecret(wrapped),
      mldsaPrivateKeyWrapKeyId: wrapped.keyId,
    };

    const rotated = rotateWrappingKey({
      stored,
      oldKeyring: oldRing,
      newKeyring: newRing,
    });
    expect(rotated.mldsaPrivateKeyWrapKeyId).toBe("wrap-key-2026-09");

    // The new envelope must be unwrappable with the new key, and the
    // recovered bytes must match the original secret (rotation is
    // lossless).
    const newWrapped = deserializeWrappedSecret(rotated.mldsaPrivateKeyWrapped);
    const recovered = Buffer.from(unwrapSecret(newWrapped, newRing));
    expect(recovered.equals(secret)).toBe(true);
  });

  it("rejects a stored identity with no wrap envelope (plaintext row)", () => {
    const oldRing = new InMemoryKeyring("wrap-key-2026-08");
    oldRing.addKey("wrap-key-2026-08", newKey());
    const newRing = new InMemoryKeyring("wrap-key-2026-09");
    newRing.addKey("wrap-key-2026-09", newKey());

    expect(() =>
      rotateWrappingKey({
        stored: {
          privateKeyPem: "MLDSA65-SECRET-KEY:abc",
          mldsaPrivateKeyWrapped: null,
          mldsaPrivateKeyWrapKeyId: null,
        },
        oldKeyring: oldRing,
        newKeyring: newRing,
      }),
    ).toThrow(/no wrap envelope/);
  });

  it("rejects a stored identity with a wrap envelope but no wrapKeyId (inconsistent)", () => {
    const oldRing = new InMemoryKeyring("wrap-key-2026-08");
    oldRing.addKey("wrap-key-2026-08", newKey());
    const newRing = new InMemoryKeyring("wrap-key-2026-09");
    newRing.addKey("wrap-key-2026-09", newKey());

    expect(() =>
      rotateWrappingKey({
        stored: {
          privateKeyPem: "MLDSA65-SECRET-KEY:abc",
          mldsaPrivateKeyWrapped: serializeWrappedSecret({
            ciphertext: "AAAA",
            iv: "AAAA",
            authTag: "AAAA",
            keyId: "wrap-key-2026-08",
          }),
          mldsaPrivateKeyWrapKeyId: null,
        },
        oldKeyring: oldRing,
        newKeyring: newRing,
      }),
    ).toThrow(/inconsistent/);
  });

  it("rejects when the old keyring has lost the wrapKeyId", () => {
    const oldRing = new InMemoryKeyring("wrap-key-2026-08");
    oldRing.addKey("wrap-key-2026-08", newKey());
    const newRing = new InMemoryKeyring("wrap-key-2026-09");
    newRing.addKey("wrap-key-2026-09", newKey());
    const secret = randomBytes(4032);
    const wrapped = wrapSecret(Buffer.from(secret), oldRing);
    const stored = {
      privateKeyPem: encodeMlDsa65SecretKey(secret),
      mldsaPrivateKeyWrapped: serializeWrappedSecret(wrapped),
      mldsaPrivateKeyWrapKeyId: wrapped.keyId,
    };
    oldRing.drop("wrap-key-2026-08");
    expect(() =>
      rotateWrappingKey({ stored, oldKeyring: oldRing, newKeyring: newRing }),
    ).toThrow(/not found|invalid/i);
  });
});

describe("exportWrapKey / importWrapKey (whitepaper 2.2.5.D)", () => {
  it("round-trips a 32-byte key under a passphrase", () => {
    const key = newKey();
    const backup = exportWrapKey({
      key,
      passphrase: "correct horse battery staple",
      keyId: "wrap-key-2026-08",
    });
    expect(backup.version).toBe(1);
    expect(backup.iterations).toBe(WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_ITERATIONS);
    expect(backup.salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(backup.iv).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(backup.ciphertext).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(backup.authTag).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(backup.keyId).toBe("wrap-key-2026-08");

    const recovered = importWrapKey({ backup, passphrase: "correct horse battery staple" });
    expect(recovered.equals(key)).toBe(true);
  });

  it("rejects the wrong passphrase (GCM auth tag fails)", () => {
    const key = newKey();
    const backup = exportWrapKey({
      key,
      passphrase: "the right one",
      keyId: "wrap-key-2026-08",
    });
    expect(() =>
      importWrapKey({ backup, passphrase: "the wrong one" }),
    ).toThrow();
  });

  it("rejects an empty passphrase", () => {
    const key = newKey();
    expect(() =>
      exportWrapKey({ key, passphrase: "", keyId: "wrap-key-2026-08" }),
    ).toThrow(/non-empty/);
  });

  it("rejects a wrong-size key on export", () => {
    const tooShort = randomBytes(16);
    expect(() =>
      exportWrapKey({ key: tooShort, passphrase: "x", keyId: "k" }),
    ).toThrow(/32-byte/);
  });

  it("rejects a malformed backup version", () => {
    const key = newKey();
    const backup = exportWrapKey({ key, passphrase: "x", keyId: "k" });
    const broken = { ...backup, version: 99 as 1 };
    expect(() => importWrapKey({ backup: broken, passphrase: "x" })).toThrow(/version/);
  });

  it("rejects a salt of wrong length", () => {
    const key = newKey();
    const backup = exportWrapKey({ key, passphrase: "x", keyId: "k" });
    const broken = { ...backup, salt: Buffer.from("AA").toString("base64url") };
    expect(() => importWrapKey({ backup: broken, passphrase: "x" })).toThrow(/salt/);
  });

  it("rejects an iv of wrong length", () => {
    const key = newKey();
    const backup = exportWrapKey({ key, passphrase: "x", keyId: "k" });
    const broken = { ...backup, iv: Buffer.from("AA").toString("base64url") };
    expect(() => importWrapKey({ backup: broken, passphrase: "x" })).toThrow(/iv/);
  });

  it("rejects a ciphertext of wrong length", () => {
    const key = newKey();
    const backup = exportWrapKey({ key, passphrase: "x", keyId: "k" });
    // Make ciphertext one byte too long.
    const broken = { ...backup, ciphertext: Buffer.from("AA").toString("base64url") };
    expect(() => importWrapKey({ backup: broken, passphrase: "x" })).toThrow(/ciphertext/);
  });

  it("rejects an empty keyId", () => {
    const key = newKey();
    const backup = exportWrapKey({ key, passphrase: "x", keyId: "k" });
    const broken = { ...backup, keyId: "" };
    expect(() => importWrapKey({ backup: broken, passphrase: "x" })).toThrow(/keyId/);
  });

  it("produces a fresh salt on every export (no salt reuse)", () => {
    const key = newKey();
    const seen = new Set<string>();
    for (let i = 0; i < 8; i += 1) {
      const backup = exportWrapKey({ key, passphrase: "x", keyId: "k" });
      expect(seen.has(backup.salt)).toBe(false);
      expect(seen.has(backup.iv)).toBe(false);
      seen.add(backup.salt);
      seen.add(backup.iv);
    }
  });

  it("uses a higher iteration count when requested (slow-rolling upgrade)", () => {
    const key = newKey();
    const backup = exportWrapKey({
      key,
      passphrase: "x",
      keyId: "k",
      iterations: WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_ITERATIONS * 2,
    });
    expect(backup.iterations).toBe(WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_ITERATIONS * 2);
    const recovered = importWrapKey({ backup, passphrase: "x" });
    expect(recovered.equals(key)).toBe(true);
  });

  it("rejects a non-positive iteration count", () => {
    const key = newKey();
    expect(() =>
      exportWrapKey({ key, passphrase: "x", keyId: "k", iterations: 0 }),
    ).toThrow(/positive integer/);
  });
});

describe("constantTimeEqual", () => {
  it("returns true for equal-length, equal-value buffers", () => {
    const a = Buffer.from("hello world!");
    const b = Buffer.from("hello world!");
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it("returns false for equal-length, different-value buffers", () => {
    const a = Buffer.from("hello world!");
    const b = Buffer.from("hello WORLD!");
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("returns false for different-length buffers", () => {
    const a = Buffer.from("abc");
    const b = Buffer.from("abcd");
    expect(constantTimeEqual(a, b)).toBe(false);
  });
});
