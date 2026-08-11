// Round-trip + tamper-detection tests for the AES-256-GCM envelope (M4 /
// whitepaper 2.2.1). The wrap/unwrap helpers do not touch the keyring; the
// test wires them to a tiny in-memory keyring so the cryptographic contract
// is the only thing under test here.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type ActiveWrappingKey,
  deserializeWrappedSecret,
  type WrappedSecret,
  type WrappingKeyProvider,
  serializeWrappedSecret,
  unwrapSecret,
  wrapSecret,
} from "./secret-wrapping.js";

/** Minimal in-memory keyring that satisfies the WrappingKeyProvider contract.
 *  Tests use it to drive the wrap/unwrap helpers without touching the
 *  real keyring module (M6 will own that). */
class InMemoryKeyring implements WrappingKeyProvider {
  private readonly activeId: string;
  private readonly keys = new Map<string, Buffer>();

  constructor(activeId: string) {
    this.activeId = activeId;
  }

  addKey(keyId: string, key: Buffer): void {
    this.keys.set(keyId, Buffer.from(key));
  }

  rotate(newActiveId: string, newKey: Buffer): void {
    this.addKey(newActiveId, newKey);
    (this as { activeId: string }).activeId = newActiveId;
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

function newKey(): Buffer {
  return randomBytes(32);
}

const FIXTURE_KEY_IDS = ["wrap-key-2026-08", "wrap-key-2026-09"] as const;

let keyring: InMemoryKeyring;
const originalKey = newKey();
const rotatedKey = newKey();

beforeEach(() => {
  keyring = new InMemoryKeyring(FIXTURE_KEY_IDS[0]);
  keyring.addKey(FIXTURE_KEY_IDS[0], originalKey);
});

afterEach(() => {
  // Zero material the test owns. node:crypto Buffer.fill(0) is enough —
  // these are ephemeral test keys, not operator-controlled secrets, so
  // the timingSafeEqual / volatile-write story that the runtime uses
  // does not apply here.
  originalKey.fill(0);
  rotatedKey.fill(0);
});

describe("AES-256-GCM wrap/unwrap (whitepaper 2.2.1)", () => {
  it("round-trips an empty buffer", () => {
    const wrapped = wrapSecret(Buffer.alloc(0), keyring);
    expect(wrapped.ciphertext).toBe("");
    expect(Buffer.from(unwrapSecret(wrapped, keyring))).toEqual(Buffer.alloc(0));
  });

  it("round-trips a short buffer (ML-DSA-65 public key sized)", () => {
    const plaintext = randomBytes(1952);
    const wrapped = wrapSecret(plaintext, keyring);
    const unwrapped = unwrapSecret(wrapped, keyring);
    expect(Buffer.from(unwrapped)).toEqual(plaintext);
  });

  it("round-trips a larger buffer (ML-DSA-65 secret key sized)", () => {
    const plaintext = randomBytes(4032);
    const wrapped = wrapSecret(plaintext, keyring);
    const unwrapped = unwrapSecret(wrapped, keyring);
    expect(Buffer.from(unwrapped)).toEqual(plaintext);
  });

  it("emits a fresh 12-byte IV on every call (GCM nonce never repeats)", () => {
    const plaintext = Buffer.from("hello pqc wrap");
    const seen = new Set<string>();
    for (let i = 0; i < 32; i += 1) {
      const wrapped = wrapSecret(plaintext, keyring);
      // 12 random bytes → 16 base64url chars.
      expect(wrapped.iv).toMatch(/^[A-Za-z0-9_-]{16}$/);
      expect(seen.has(wrapped.iv)).toBe(false);
      seen.add(wrapped.iv);
    }
    expect(seen.size).toBe(32);
  });

  it("emits a 16-byte auth tag (GCM standard)", () => {
    const wrapped = wrapSecret(Buffer.from("x"), keyring);
    expect(Buffer.from(wrapped.authTag, "base64url").length).toBe(16);
  });

  it("emits a ciphertext of exactly plaintext.length bytes", () => {
    for (const size of [0, 1, 16, 1952, 4032, 1 << 14]) {
      const plaintext = randomBytes(size);
      const wrapped = wrapSecret(plaintext, keyring);
      expect(Buffer.from(wrapped.ciphertext, "base64url").length).toBe(size);
    }
  });

  it("records the keyId that sealed the payload", () => {
    const wrapped = wrapSecret(Buffer.from("x"), keyring);
    expect(wrapped.keyId).toBe(FIXTURE_KEY_IDS[0]);
  });

  it("rejects a tampered ciphertext (auth tag fails GCM verification)", () => {
    const wrapped = wrapSecret(Buffer.from("the quick brown fox"), keyring);
    const tampered: WrappedSecret = {
      ...wrapped,
      // Flip a bit in the middle of the ciphertext. The length stays
      // the same so the failure is unambiguously from GCM, not from a
      // length check.
      ciphertext: Buffer.from(wrapped.ciphertext, "base64url")
        .map((b, i) => (i === 5 ? b ^ 0x01 : b))
        .toString("base64url"),
    };
    expect(() => unwrapSecret(tampered, keyring)).toThrow();
  });

  it("rejects a tampered auth tag", () => {
    const wrapped = wrapSecret(Buffer.from("the quick brown fox"), keyring);
    const tampered: WrappedSecret = {
      ...wrapped,
      authTag: Buffer.from(wrapped.authTag, "base64url")
        .map((b, i) => (i === 0 ? b ^ 0x80 : b))
        .toString("base64url"),
    };
    expect(() => unwrapSecret(tampered, keyring)).toThrow();
  });

  it("rejects a tampered IV", () => {
    const wrapped = wrapSecret(Buffer.from("the quick brown fox"), keyring);
    const tampered: WrappedSecret = {
      ...wrapped,
      iv: Buffer.from(wrapped.iv, "base64url")
        .map((b, i) => (i === 0 ? b ^ 0x01 : b))
        .toString("base64url"),
    };
    expect(() => unwrapSecret(tampered, keyring)).toThrow();
  });

  it("rejects unwrap with a different (wrong-size) key under the same keyId", () => {
    const wrapped = wrapSecret(Buffer.from("the quick brown fox"), keyring);
    // The wrong keyring has the SAME keyId as the wrap, but a 16-byte
    // (AES-128 sized) key. The size check must fire before GCM
    // initialisation, otherwise we'd silently truncate.
    const wrongKeyring = new InMemoryKeyring(FIXTURE_KEY_IDS[0]);
    wrongKeyring.addKey(FIXTURE_KEY_IDS[0], randomBytes(16));
    expect(() => unwrapSecret(wrapped, wrongKeyring)).toThrow(/32 bytes/);
  });

  it("rejects unwrap when the keyring has dropped the keyId entirely", () => {
    const wrapped = wrapSecret(Buffer.from("the quick brown fox"), keyring);
    // The keyring's active key has rotated AND the historical key has
    // been explicitly removed (the M7 rotation path does this after
    // a grace period). unwrapSecret must fail-closed so a removed key
    // cannot silently lose a previously-wrapped device identity.
    keyring.drop(FIXTURE_KEY_IDS[0]);
    keyring.rotate(FIXTURE_KEY_IDS[1], rotatedKey);
    expect(() => unwrapSecret(wrapped, keyring)).toThrow(/not found/);
  });

  it("rejects a wrap when the active key is the wrong size", () => {
    const brokenKeyring = new InMemoryKeyring("wrap-key-bad");
    brokenKeyring.addKey("wrap-key-bad", randomBytes(24));
    expect(() => wrapSecret(Buffer.from("x"), brokenKeyring)).toThrow(/32 bytes/);
  });

  it("rejects a non-Buffer plaintext", () => {
    expect(() =>
      wrapSecret("not a buffer" as unknown as Buffer, keyring),
    ).toThrow(/Buffer/);
  });
});

describe("serialize/deserialize (whitepaper 2.2.1)", () => {
  it("round-trips a WrappedSecret through the SQLite BLOB format", () => {
    const wrapped = wrapSecret(Buffer.from("sqlite round-trip"), keyring);
    const serialized = serializeWrappedSecret(wrapped);
    // The serialized form is base64url, never raw JSON, so the SQLite
    // BLOB column sees bytes and the JSON1 extension is not required.
    expect(serialized).toMatch(/^[A-Za-z0-9_-]+$/);
    const deserialized = deserializeWrappedSecret(serialized);
    expect(deserialized).toEqual(wrapped);
  });

  it("produces a deterministic serialization for an equal WrappedSecret", () => {
    const wrapped = wrapSecret(Buffer.from("x"), keyring);
    const a = serializeWrappedSecret(wrapped);
    const b = serializeWrappedSecret(wrapped);
    expect(a).toBe(b);
  });

  it("rejects an empty / non-string input", () => {
    expect(() => deserializeWrappedSecret("")).toThrow(/non-empty/);
    expect(() => deserializeWrappedSecret(undefined as unknown as string)).toThrow(
      /non-empty/,
    );
  });

  it("rejects a malformed base64url payload", () => {
    // Truncated half a byte (length mod 4 === 2 means missing 2 chars
    // of base64url padding in some encoders; here we just feed junk).
    const garbage = "@@@not-base64url@@@";
    expect(() => deserializeWrappedSecret(garbage)).toThrow();
  });

  it("rejects a base64url payload that decodes to non-JSON", () => {
    const notJson = Buffer.from("not json", "utf8").toString("base64url");
    expect(() => deserializeWrappedSecret(notJson)).toThrow(/malformed/);
  });

  it("rejects a JSON payload missing required fields", () => {
    for (const missing of [
      JSON.stringify({ iv: "a", authTag: "b", keyId: "c" }),
      JSON.stringify({ ciphertext: "a", authTag: "b", keyId: "c" }),
      JSON.stringify({ ciphertext: "a", iv: "b", keyId: "c" }),
      JSON.stringify({ ciphertext: "a", iv: "b", authTag: "c" }),
    ]) {
      const serialized = Buffer.from(missing, "utf8").toString("base64url");
      expect(() => deserializeWrappedSecret(serialized)).toThrow();
    }
  });

  it("rejects a JSON payload with the wrong field types", () => {
    const wrongTypes = JSON.stringify({
      ciphertext: 1,
      iv: "a",
      authTag: "b",
      keyId: "c",
    });
    const serialized = Buffer.from(wrongTypes, "utf8").toString("base64url");
    expect(() => deserializeWrappedSecret(serialized)).toThrow(/ciphertext/);
  });

  it("rejects an empty keyId", () => {
    const empty = JSON.stringify({
      ciphertext: "a",
      iv: "b",
      authTag: "c",
      keyId: "",
    });
    const serialized = Buffer.from(empty, "utf8").toString("base64url");
    expect(() => deserializeWrappedSecret(serialized)).toThrow(/keyId/);
  });
});

describe("wrap → serialize → deserialize → unwrap end-to-end", () => {
  it("preserves the plaintext bytes through the full SQLite-shaped pipeline", () => {
    const plaintext = randomBytes(4032);
    const wrapped = wrapSecret(plaintext, keyring);
    const serialized = serializeWrappedSecret(wrapped);
    // Mirror the SQLite storage path: store as BLOB, read as BLOB,
    // re-encode as the same base64url string.
    const roundTripped = deserializeWrappedSecret(serialized);
    const recovered = unwrapSecret(roundTripped, keyring);
    expect(timingSafeEqual(Buffer.from(recovered), plaintext)).toBe(true);
    // SHA-256 spot check so a silent re-encoding bug cannot pass a
    // length-equal-but-corrupted buffer.
    expect(createHash("sha256").update(recovered).digest("hex")).toBe(
      createHash("sha256").update(plaintext).digest("hex"),
    );
  });
});
