// PQC fork M6: Keyring providers — File / Env / Composite (whitepaper 2.2.5 + 2.2.5.A).
//
// The OS keyring (@napi-rs/keyring) is a separate milestone (M6.B) and
// is not exercised here; the stub at `os-keyring.ts` refuses to
// construct so a misconfigured `{kind:"os"}` fails fast.
//
// Tests focus on the cryptographic / encoding contract — the 32-byte
// AES-256 length check, the base64url wire format, the file-mode
// guard, the env-var rotation, and the composite's first-match wins
// rule for `getKeyById` / first-success for `getActiveKey`.
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type ActiveWrappingKey,
  CompositeKeyring,
  createKeyring,
  decodeBase64UrlKey,
  encodeBase64UrlKey,
  EnvKeyring,
  FileKeyring,
  generateWrappingKey,
  getDefaultKeyringFromEnv,
  type KeyringProvider,
  OsKeyring,
  resetDefaultKeyringCache,
} from "./keyring-provider.js";
import { unwrapSecret, wrapSecret } from "./secret-wrapping.js";

const tempDirs: string[] = [];
const trackedKeys: Buffer[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m6-"));
  tempDirs.push(dir);
  return dir;
}

function newKey(): Buffer {
  const k = randomBytes(32);
  trackedKeys.push(k);
  return k;
}

function readKeyFile(filePath: string): Buffer {
  // Authorised test-only reader that flips the file mode off
  // briefly (via a clone with 0600) so the production FileKeyring
  // can load the key without triggering the safety guard.
  const raw = fs.readFileSync(filePath, "utf8").trim();
  return decodeBase64UrlKey(raw, `file:${filePath}`);
}

function writeKeyFile(filePath: string, key: Buffer, mode: number = 0o600): void {
  fs.writeFileSync(filePath, encodeBase64UrlKey(key));
  if (process.platform !== "win32") {
    fs.chmodSync(filePath, mode);
  }
}

beforeEach(() => {
  while (tempDirs.length > 0) tempDirs.pop();
  while (trackedKeys.length > 0) trackedKeys.pop();
});

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (!dir) continue;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
  }
  while (trackedKeys.length > 0) {
    trackedKeys.pop()?.fill(0);
  }
});

describe("encodeBase64UrlKey / decodeBase64UrlKey (wire format)", () => {
  it("round-trips a 32-byte key", () => {
    const key = newKey();
    const encoded = encodeBase64UrlKey(key);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(decodeBase64UrlKey(encoded, "test")).toEqual(key);
  });

  it("rejects a wrong-size input on decode", () => {
    expect(() => decodeBase64UrlKey("AAAA", "test")).toThrow(/32 bytes/);
    // 31 bytes after base64url decode
    const tooShort = Buffer.alloc(31).toString("base64url");
    expect(() => decodeBase64UrlKey(tooShort, "test")).toThrow(/32 bytes/);
    // 33 bytes after base64url decode
    const tooLong = Buffer.alloc(33).toString("base64url");
    expect(() => decodeBase64UrlKey(tooLong, "test")).toThrow(/32 bytes/);
  });

  it("rejects an empty / non-string input", () => {
    expect(() => decodeBase64UrlKey("", "test")).toThrow(/non-empty/);
  });

  it("rejects a wrong-size key on encode", () => {
    const tooShort = Buffer.alloc(16);
    expect(() => encodeBase64UrlKey(tooShort)).toThrow(/32 bytes/);
  });
});

describe("FileKeyring (whitepaper 2.2.5 — file backend)", () => {
  it("reads a 32-byte key from an absolute file path", () => {
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    const key = newKey();
    writeKeyFile(keyPath, key);

    const ring = new FileKeyring(keyPath, "wrap-key-2026-08");
    const active = ring.getActiveKey();
    expect(active.key).toEqual(key);
    expect(active.keyId).toBe("wrap-key-2026-08");
    expect(ring.getKeyById("wrap-key-2026-08")).toEqual(key);
    expect(ring.getKeyById("unknown")).toBeNull();
  });

  it("rejects a relative path", () => {
    expect(() => new FileKeyring("wrap.key", "wrap-key-2026-08")).toThrow(
      /absolute/,
    );
  });

  it("rejects an empty keyPath", () => {
    expect(() => new FileKeyring("", "wrap-key-2026-08")).toThrow(/non-empty/);
  });

  it("throws when the key file does not exist", () => {
    const dir = makeTempDir();
    const ring = new FileKeyring(path.join(dir, "missing.key"));
    expect(() => ring.getActiveKey()).toThrow(/not found/);
  });

  it("refuses world- or group-readable files on POSIX", () => {
    if (process.platform === "win32") {
      return; // POSIX-only check; skip on Windows.
    }
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    const key = newKey();
    writeKeyFile(keyPath, key, 0o644); // owner rw, group r, world r
    const ring = new FileKeyring(keyPath);
    expect(() => ring.getActiveKey()).toThrow(/unsafe permissions/);
  });

  it("caches the key on first read and honours `invalidate()`", () => {
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    const key = newKey();
    writeKeyFile(keyPath, key);

    const ring = new FileKeyring(keyPath);
    const first = ring.getActiveKey();
    expect(first.key).toEqual(key);
    // Overwrite the file. The cached value must still come back
    // because `invalidate()` was not called — this protects against
    // an external rotation that does not flow through the M7 path.
    const newKeyBuf = newKey();
    writeKeyFile(keyPath, newKeyBuf);
    const cached = ring.getActiveKey();
    expect(cached.key).toEqual(key);
    ring.invalidate();
    const after = ring.getActiveKey();
    expect(after.key).toEqual(newKeyBuf);
  });

  it("survives a wrap + unwrap round-trip through the device-identity wrap envelope", () => {
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    const key = newKey();
    writeKeyFile(keyPath, key);
    const ring = new FileKeyring(keyPath, "wrap-key-2026-08");
    const wrapped = wrapSecret(Buffer.from("the quick brown fox"), ring);
    expect(wrapped.keyId).toBe("wrap-key-2026-08");
    expect(Buffer.from(unwrapSecret(wrapped, ring)).toString("utf8")).toBe(
      "the quick brown fox",
    );
  });
});

describe("EnvKeyring (whitepaper 2.2.5 — env backend)", () => {
  it("reads a 32-byte key from a process env var", () => {
    const key = newKey();
    const env: NodeJS.ProcessEnv = { OPENCLAW_TEST_KEY: encodeBase64UrlKey(key) };
    const ring = new EnvKeyring("OPENCLAW_TEST_KEY", env, "wrap-key-2026-08");
    const active = ring.getActiveKey();
    expect(active.key).toEqual(key);
    expect(active.keyId).toBe("wrap-key-2026-08");
  });

  it("throws when the env var is missing", () => {
    const ring = new EnvKeyring("OPENCLAW_NOT_SET", {}, "wrap-key-2026-08");
    expect(() => ring.getActiveKey()).toThrow(/not set/);
  });

  it("throws when the env var is empty", () => {
    const ring = new EnvKeyring("OPENCLAW_EMPTY", { OPENCLAW_EMPTY: "" }, "wrap-key");
    expect(() => ring.getActiveKey()).toThrow(/not set/);
  });

  it("re-reads the env var on every call (no cache)", () => {
    const key = newKey();
    const envStore: NodeJS.ProcessEnv = {};
    envStore.OPENCLAW_TEST_KEY = encodeBase64UrlKey(key);
    const ring = new EnvKeyring("OPENCLAW_TEST_KEY", envStore, "wrap-key");
    const first = ring.getActiveKey();
    expect(first.key).toEqual(key);
    // Rotate the env var.
    const rotated = newKey();
    envStore.OPENCLAW_TEST_KEY = encodeBase64UrlKey(rotated);
    const second = ring.getActiveKey();
    expect(second.key).toEqual(rotated);
  });

  it("rejects an empty env name at construction", () => {
    expect(() => new EnvKeyring("", {}, "wrap-key")).toThrow(/non-empty/);
  });
});

describe("CompositeKeyring (whitepaper 2.2.5.A — auto-inject default)", () => {
  it("returns the first provider's active key on success", () => {
    const a = newKey();
    const b = newKey();
    const env: NodeJS.ProcessEnv = {
      OPENCLAW_TEST_KEY_A: encodeBase64UrlKey(a),
      OPENCLAW_TEST_KEY_B: encodeBase64UrlKey(b),
    };
    const primary = new EnvKeyring("OPENCLAW_TEST_KEY_A", env, "primary");
    const fallback = new EnvKeyring("OPENCLAW_TEST_KEY_B", env, "fallback");
    const composite = new CompositeKeyring([primary, fallback]);
    const active = composite.getActiveKey();
    expect(active.key).toEqual(a);
    expect(active.keyId).toBe("primary");
  });

  it("falls back to the next provider when the primary fails", () => {
    const b = newKey();
    const env: NodeJS.ProcessEnv = { OPENCLAW_TEST_KEY_B: encodeBase64UrlKey(b) };
    const primary = new EnvKeyring("OPENCLAW_MISSING", env, "primary");
    const fallback = new EnvKeyring("OPENCLAW_TEST_KEY_B", env, "fallback");
    const composite = new CompositeKeyring([primary, fallback]);
    const active = composite.getActiveKey();
    expect(active.key).toEqual(b);
    expect(active.keyId).toBe("fallback");
  });

  it("throws a descriptive error when every provider fails", () => {
    const composite = new CompositeKeyring([
      new EnvKeyring("OPENCLAW_NOT_SET_1", {}, "primary"),
      new EnvKeyring("OPENCLAW_NOT_SET_2", {}, "fallback"),
    ]);
    expect(() => composite.getActiveKey()).toThrow(/no provider returned/);
  });

  it("getKeyById walks every provider in order", () => {
    const a = newKey();
    const b = newKey();
    const env: NodeJS.ProcessEnv = {
      OPENCLAW_TEST_KEY_A: encodeBase64UrlKey(a),
      OPENCLAW_TEST_KEY_B: encodeBase64UrlKey(b),
    };
    const composite = new CompositeKeyring([
      new EnvKeyring("OPENCLAW_TEST_KEY_A", env, "key-a"),
      new EnvKeyring("OPENCLAW_TEST_KEY_B", env, "key-b"),
    ]);
    expect(composite.getKeyById("key-a")).toEqual(a);
    expect(composite.getKeyById("key-b")).toEqual(b);
    expect(composite.getKeyById("unknown")).toBeNull();
  });

  it("rejects an empty providers list", () => {
    expect(() => new CompositeKeyring([])).toThrow(/non-empty/);
  });
});

describe("createKeyring (factory)", () => {
  it("builds a FileKeyring from {kind:\"file\"}", () => {
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    const key = newKey();
    writeKeyFile(keyPath, key);
    const ring = createKeyring({ kind: "file", keyPath });
    expect(ring).toBeInstanceOf(FileKeyring);
    expect(ring.getActiveKey().key).toEqual(key);
  });

  it("builds an EnvKeyring from {kind:\"env\"}", () => {
    const key = newKey();
    const env: NodeJS.ProcessEnv = { OPENCLAW_TEST_KEY: encodeBase64UrlKey(key) };
    const originalEnv = process.env.OPENCLAW_TEST_KEY;
    process.env.OPENCLAW_TEST_KEY = encodeBase64UrlKey(key);
    try {
      const ring = createKeyring({ kind: "env", envName: "OPENCLAW_TEST_KEY" });
      expect(ring).toBeInstanceOf(EnvKeyring);
      expect(ring.getActiveKey().key).toEqual(key);
    } finally {
      if (originalEnv === undefined) {
        delete process.env.OPENCLAW_TEST_KEY;
      } else {
        process.env.OPENCLAW_TEST_KEY = originalEnv;
      }
    }
  });

  it("builds an OsKeyring stub from {kind:\"os\"} and refuses to construct-then-call", () => {
    const ring = createKeyring({
      kind: "os",
      service: "openclaw",
      account: "device-identity",
    });
    expect(ring).toBeInstanceOf(OsKeyring);
    expect(() => ring.getActiveKey()).toThrow(/not implemented/);
  });

  it("builds a CompositeKeyring from {kind:\"composite\"}", () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, "wrap.key");
    const key = newKey();
    writeKeyFile(filePath, key);
    const ring = createKeyring({
      kind: "composite",
      providers: [
        { kind: "env", envName: "OPENCLAW_NOT_SET" },
        { kind: "file", keyPath: filePath },
      ],
    });
    expect(ring).toBeInstanceOf(CompositeKeyring);
    expect(ring.getActiveKey().key).toEqual(key);
  });
});

describe("OsKeyring (stub for whitepaper 2.2.5.B)", () => {
  it("rejects an empty service or account", () => {
    expect(() => new OsKeyring("", "x")).toThrow(/service/);
    expect(() => new OsKeyring("x", "")).toThrow(/account/);
  });

  it("fails closed on getActiveKey with a clear message", () => {
    const ring = new OsKeyring("openclaw", "device-identity");
    expect(() => ring.getActiveKey()).toThrow(/M6\.B/);
  });

  it("fails closed on getKeyById", () => {
    const ring = new OsKeyring("openclaw", "device-identity");
    expect(() => ring.getKeyById("wrap-key-2026-08")).toThrow(/M6\.B/);
  });
});

describe("generateWrappingKey (M8 CLI helper)", () => {
  it("returns a 32-byte key", () => {
    const k = generateWrappingKey();
    expect(k.length).toBe(32);
  });

  it("returns different keys across calls", () => {
    const a = generateWrappingKey();
    const b = generateWrappingKey();
    expect(a.equals(b)).toBe(false);
  });
});

describe("getDefaultKeyringFromEnv (M5.5 auto-inject — whitepaper 2.2.5.A)", () => {
  // Each test mutates a single env-var set, so save the original and
  // restore it in afterEach. The module-level cache is reset between
  // tests via `resetDefaultKeyringCache()` so the env-var changes are
  // observable on the next call.
  const originalFile = process.env.OPENCLAW_WRAP_KEY_FILE;
  const originalId = process.env.OPENCLAW_WRAP_KEY_ID;

  afterEach(() => {
    if (originalFile === undefined) {
      delete process.env.OPENCLAW_WRAP_KEY_FILE;
    } else {
      process.env.OPENCLAW_WRAP_KEY_FILE = originalFile;
    }
    if (originalId === undefined) {
      delete process.env.OPENCLAW_WRAP_KEY_ID;
    } else {
      process.env.OPENCLAW_WRAP_KEY_ID = originalId;
    }
    resetDefaultKeyringCache();
  });

  it("returns null when OPENCLAW_WRAP_KEY_FILE is unset", () => {
    delete process.env.OPENCLAW_WRAP_KEY_FILE;
    resetDefaultKeyringCache();
    expect(getDefaultKeyringFromEnv()).toBeNull();
  });

  it("returns null when OPENCLAW_WRAP_KEY_FILE is empty", () => {
    process.env.OPENCLAW_WRAP_KEY_FILE = "";
    resetDefaultKeyringCache();
    expect(getDefaultKeyringFromEnv()).toBeNull();
  });

  it("returns a FileKeyring when the env var points to a real key file", () => {
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    const key = newKey();
    writeKeyFile(keyPath, key);
    process.env.OPENCLAW_WRAP_KEY_FILE = keyPath;
    process.env.OPENCLAW_WRAP_KEY_ID = "wrap-key-2026-08";
    resetDefaultKeyringCache();

    const ring = getDefaultKeyringFromEnv();
    expect(ring).not.toBeNull();
    expect(ring).toBeInstanceOf(FileKeyring);
    const active = ring!.getActiveKey();
    expect(active.keyId).toBe("wrap-key-2026-08");
    expect(active.key).toEqual(key);
  });

  it("defaults the keyId to 'file-keyring' when OPENCLAW_WRAP_KEY_ID is unset", () => {
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    writeKeyFile(keyPath, newKey());
    process.env.OPENCLAW_WRAP_KEY_FILE = keyPath;
    delete process.env.OPENCLAW_WRAP_KEY_ID;
    resetDefaultKeyringCache();

    const ring = getDefaultKeyringFromEnv();
    expect(ring).not.toBeNull();
    expect(ring!.getActiveKey().keyId).toBe("file-keyring");
  });

  it("caches the FileKeyring instance across calls (replaces M5.5 v1/v2 runtime patch)", () => {
    const dir = makeTempDir();
    const keyPath = path.join(dir, "wrap.key");
    writeKeyFile(keyPath, newKey());
    process.env.OPENCLAW_WRAP_KEY_FILE = keyPath;
    process.env.OPENCLAW_WRAP_KEY_ID = "wrap-key-2026-08";
    resetDefaultKeyringCache();

    const a = getDefaultKeyringFromEnv();
    const b = getDefaultKeyringFromEnv();
    // The M5.5 v1/v2 runtime patches constructed a fresh keyring on
    // every call, defeating `FileKeyring`'s `cachedKey` instance field.
    // Auto-inject must hand back the same instance so the built-in
    // cache survives across the 12+ startup callers.
    expect(a).toBe(b);
  });

  it("rejects a relative key path (FileKeyring's own guard, not bypassed by auto-inject)", () => {
    process.env.OPENCLAW_WRAP_KEY_FILE = "wrap.key";
    resetDefaultKeyringCache();
    // FileKeyring's constructor throws on relative paths; auto-inject
    // must surface that error rather than swallowing it.
    expect(() => getDefaultKeyringFromEnv()).toThrow(/absolute/);
    // The throw means the module-level cache stays "undefined" (the
    // early-return path in `getDefaultKeyringFromEnv` runs after the
    // constructor) — verify the next call retries the construction.
    resetDefaultKeyringCache();
    expect(() => getDefaultKeyringFromEnv()).toThrow(/absolute/);
  });
});
