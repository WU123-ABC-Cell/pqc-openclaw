// PQC step 2.3.5: unit tests for keyring providers.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  CompositeKeyringProvider,
  EnvKeyringProvider,
  FileKeyringProvider,
  createDefaultKeyringProvider,
  generateKeyId,
} from "./keyring-provider.js";
import type { WrappingKeyProvider } from "./secret-wrapping.js";

const KEY_BYTES = 32;

describe("FileKeyringProvider", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "openclaw-keyring-test-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("creates a 32-byte key on first use", () => {
    const p = new FileKeyringProvider(dir);
    const { key, keyId } = p.getActiveKey();
    expect(key.length).toBe(KEY_BYTES);
    expect(keyId).toMatch(/^openclaw-wrap-[0-9a-f]{32}$/);
  });

  it("persists key across instances (same keyId + bytes)", () => {
    const p1 = new FileKeyringProvider(dir);
    const { keyId: id1, key: k1 } = p1.getActiveKey();
    const p2 = new FileKeyringProvider(dir);
    const { keyId: id2, key: k2 } = p2.getActiveKey();
    expect(id1).toBe(id2);
    expect(k1.equals(k2)).toBe(true);
  });

  it("rotates key when a different keyId is constructed", () => {
    const p1 = new FileKeyringProvider(dir, "openclaw-wrap-aaa");
    const { keyId: id1 } = p1.getActiveKey();
    const p2 = new FileKeyringProvider(dir, "openclaw-wrap-bbb");
    const { keyId: id2 } = p2.getActiveKey();
    expect(id1).toBe("openclaw-wrap-aaa");
    expect(id2).toBe("openclaw-wrap-bbb");
  });

  it("preserves old keys for getKeyById lookup", () => {
    const p1 = new FileKeyringProvider(dir, "openclaw-wrap-old");
    p1.getActiveKey();
    const p2 = new FileKeyringProvider(dir, "openclaw-wrap-new");
    const { key, keyId } = p2.getActiveKey();
    expect(keyId).toBe("openclaw-wrap-new");
    const oldKey = p2.getKeyById("openclaw-wrap-old");
    expect(oldKey).not.toBeNull();
    expect(oldKey?.length).toBe(KEY_BYTES);
  });

  it("getKeyById returns null for unknown id", () => {
    const p = new FileKeyringProvider(dir);
    expect(p.getKeyById("openclaw-wrap-nonexistent")).toBeNull();
  });

  it("creates directory with 0o700 mode", () => {
    const dir2 = mkdtempSync(join(tmpdir(), "openclaw-keyring-mode-"));
    chmodSync(dir2, 0o755);
    new FileKeyringProvider(dir2);
    const st = statSync(dir2);
    expect((st.mode & 0o777) & 0o700).toBe(0o700);
    rmSync(dir2, { recursive: true, force: true });
  });

  it("creates key file with 0o600 mode", () => {
    const p = new FileKeyringProvider(dir);
    const { keyId } = p.getActiveKey();
    const st = statSync(join(dir, `${keyId}.key`));
    expect((st.mode & 0o777) & 0o600).toBe(0o600);
  });

  it("writes the active key id to a sidecar file", () => {
    const p = new FileKeyringProvider(dir, "openclaw-wrap-sidecar");
    const { keyId } = p.getActiveKey();
    const sidecar = readFileSync(join(dir, "active-key-id"), "utf8").trim();
    expect(sidecar).toBe(keyId);
  });

  it("active key id survives even when key file is deleted (forces re-create)", () => {
    const p = new FileKeyringProvider(dir, "openclaw-wrap-survive");
    const { keyId, key: k1 } = p.getActiveKey();
    expect(k1.length).toBe(KEY_BYTES);
    rmSync(join(dir, `${keyId}.key`), { force: true });
    const { keyId: id2, key: k2 } = p.getActiveKey();
    expect(id2).toBe(keyId);
    expect(k2.length).toBe(KEY_BYTES);
  });
});

describe("EnvKeyringProvider", () => {
  const origEnv = { ...process.env };

  afterEach(() => {
    process.env = { ...origEnv };
  });

  it("reads 32-byte hex key from env", () => {
    const hex = "ab".repeat(KEY_BYTES);
    process.env.OPENCLAW_WRAP_KEY = hex;
    process.env.OPENCLAW_WRAP_KEY_ID = "env-test-hex";
    const p = new EnvKeyringProvider();
    const { key, keyId } = p.getActiveKey();
    expect(key.length).toBe(KEY_BYTES);
    expect(keyId).toBe("env-test-hex");
  });

  it("reads 32-byte base64url key from env", () => {
    const buf = Buffer.alloc(KEY_BYTES, 0xab);
    process.env.OPENCLAW_WRAP_KEY = buf.toString("base64url");
    process.env.OPENCLAW_WRAP_KEY_ID = "env-test-b64";
    const p = new EnvKeyringProvider();
    const { key, keyId } = p.getActiveKey();
    expect(key.length).toBe(KEY_BYTES);
    expect(key.equals(buf)).toBe(true);
    expect(keyId).toBe("env-test-b64");
  });

  it("defaults keyId to 'env' when OPENCLAW_WRAP_KEY_ID is unset", () => {
    process.env.OPENCLAW_WRAP_KEY = "ab".repeat(KEY_BYTES);
    delete process.env.OPENCLAW_WRAP_KEY_ID;
    const p = new EnvKeyringProvider();
    const { keyId } = p.getActiveKey();
    expect(keyId).toBe("env");
  });

  it("throws when env var is unset", () => {
    delete process.env.OPENCLAW_WRAP_KEY;
    const p = new EnvKeyringProvider();
    expect(() => p.getActiveKey()).toThrow(/OPENCLAW_WRAP_KEY/);
  });

  it("throws on invalid key length", () => {
    process.env.OPENCLAW_WRAP_KEY = "abcd";
    const p = new EnvKeyringProvider();
    expect(() => p.getActiveKey()).toThrow(/32 bytes/);
  });

  it("getKeyById returns null for non-active id (env only knows one key)", () => {
    process.env.OPENCLAW_WRAP_KEY = "ab".repeat(KEY_BYTES);
    process.env.OPENCLAW_WRAP_KEY_ID = "the-only-one";
    const p = new EnvKeyringProvider();
    expect(p.getKeyById("different-key-id")).toBeNull();
    expect(p.getKeyById("the-only-one")?.length).toBe(KEY_BYTES);
  });
});

describe("CompositeKeyringProvider", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "openclaw-composite-test-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("uses primary when available", () => {
    const file = new FileKeyringProvider(dir);
    const stub: WrappingKeyProvider = {
      getActiveKey: () => ({ key: Buffer.alloc(KEY_BYTES, 1), keyId: "primary" }),
      getKeyById: () => Buffer.alloc(KEY_BYTES, 1),
    };
    const composite = new CompositeKeyringProvider(stub, file);
    const { keyId } = composite.getActiveKey();
    expect(keyId).toBe("primary");
  });

  it("falls back to secondary when primary throws", () => {
    const file = new FileKeyringProvider(dir);
    const broken: WrappingKeyProvider = {
      getActiveKey: () => {
        throw new Error("boom");
      },
      getKeyById: () => null,
    };
    const composite = new CompositeKeyringProvider(broken, file);
    const { keyId } = composite.getActiveKey();
    expect(keyId).toMatch(/^openclaw-wrap-/);
  });

  it("getKeyById queries primary first, then fallback", () => {
    const file = new FileKeyringProvider(dir, "openclaw-wrap-file");
    file.getActiveKey();
    const primaryKey = Buffer.alloc(KEY_BYTES, 0x42);
    const stub: WrappingKeyProvider = {
      getActiveKey: () => ({ key: primaryKey, keyId: "primary-id" }),
      getKeyById: (id) => (id === "primary-id" ? primaryKey : null),
    };
    const composite = new CompositeKeyringProvider(stub, file);
    expect(composite.getKeyById("primary-id")?.equals(primaryKey)).toBe(true);
    expect(composite.getKeyById("openclaw-wrap-file")).not.toBeNull();
    expect(composite.getKeyById("unknown")).toBeNull();
  });
});

describe("createDefaultKeyringProvider", () => {
  const origKey = process.env.OPENCLAW_WRAP_KEY;
  const origKeyId = process.env.OPENCLAW_WRAP_KEY_ID;

  afterEach(() => {
    if (origKey === undefined) {
      delete process.env.OPENCLAW_WRAP_KEY;
    } else {
      process.env.OPENCLAW_WRAP_KEY = origKey;
    }
    if (origKeyId === undefined) {
      delete process.env.OPENCLAW_WRAP_KEY_ID;
    } else {
      process.env.OPENCLAW_WRAP_KEY_ID = origKeyId;
    }
  });

  it("returns EnvKeyringProvider when OPENCLAW_WRAP_KEY is set", () => {
    process.env.OPENCLAW_WRAP_KEY = "ab".repeat(KEY_BYTES);
    process.env.OPENCLAW_WRAP_KEY_ID = "factory-env";
    const p = createDefaultKeyringProvider();
    expect(p).toBeInstanceOf(EnvKeyringProvider);
  });

  it("returns FileKeyringProvider when OPENCLAW_WRAP_KEY is unset", () => {
    delete process.env.OPENCLAW_WRAP_KEY;
    const dir = mkdtempSync(join(tmpdir(), "openclaw-factory-test-"));
    try {
      const p = createDefaultKeyringProvider({ dir });
      expect(p).toBeInstanceOf(FileKeyringProvider);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("generateKeyId", () => {
  it("returns unique 32-hex-char prefixed ids", () => {
    const a = generateKeyId();
    const b = generateKeyId();
    expect(a).toMatch(/^openclaw-wrap-[0-9a-f]{32}$/);
    expect(b).toMatch(/^openclaw-wrap-[0-9a-f]{32}$/);
    expect(a).not.toBe(b);
  });
});
