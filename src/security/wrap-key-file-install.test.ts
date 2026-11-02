import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { FileKeyring } from "./keyring-provider.js";
import { prepareFileWrappingKey, resolveWrappingKeyVaultPath } from "./wrap-key-file-install.js";

const roots: string[] = [];

function stateDir(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "wrap-key-install-"));
  roots.push(root);
  const state = path.join(root, "state");
  fs.mkdirSync(state);
  return state;
}

afterEach(() => {
  for (const root of roots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

it("creates a distinct private key slot that a fresh provider can reopen", () => {
  const state = stateDir();
  const legacy = path.join(state, "wrap-key.b64");
  fs.writeFileSync(legacy, Buffer.alloc(32, 1).toString("base64url"), { mode: 0o600 });
  const before = fs.readFileSync(legacy);
  const installed = prepareFileWrappingKey(state, "key-new");
  expect(installed).toEqual({
    keyId: "key-new",
    keyPath: path.join(resolveWrappingKeyVaultPath(state), "key-new.b64"),
  });
  expect(fs.readFileSync(legacy)).toEqual(before);
  expect(fs.readFileSync(installed.keyPath, "utf8")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  if (process.platform !== "win32") {
    expect(fs.statSync(installed.keyPath).mode & 0o077).toBe(0);
    expect(fs.statSync(path.dirname(installed.keyPath)).mode & 0o077).toBe(0);
  }
  const restarted = new FileKeyring(installed.keyPath, installed.keyId);
  try {
    expect(restarted.getActiveKey().key).toHaveLength(32);
    expect(restarted.getKeyById("key-new")).toEqual(restarted.getActiveKey().key);
    if (process.platform !== "win32") {
      const alias = path.join(state, "key-alias.b64");
      fs.linkSync(installed.keyPath, alias);
      expect(() => restarted.assertCachedKeyStillInstalled()).toThrow(/private file/);
      fs.unlinkSync(alias);
      restarted.assertCachedKeyStillInstalled();
    }
  } finally {
    restarted.release();
  }
  expect(() => prepareFileWrappingKey(state, "key-new")).toThrow(/inspect/);
  expect(fs.readFileSync(installed.keyPath, "utf8")).toMatch(/^[A-Za-z0-9_-]{43}$/u);
});

it("rejects invalid IDs and an unsafe existing vault without writing a key", () => {
  const state = stateDir();
  expect(() => prepareFileWrappingKey(state, "../escape")).toThrow(/ID must contain/);
  const vault = resolveWrappingKeyVaultPath(state);
  fs.mkdirSync(vault, { mode: 0o700 });
  if (process.platform !== "win32") {
    fs.chmodSync(vault, 0o777);
    expect(() => prepareFileWrappingKey(state, "safe-id")).toThrow(/private real directory/);
    expect(fs.existsSync(path.join(vault, "safe-id.b64"))).toBe(false);
    fs.chmodSync(vault, 0o700);
    fs.chmodSync(path.dirname(vault), 0o777);
    expect(() => prepareFileWrappingKey(state, "safe-id")).toThrow(/untrusted ancestor/);
    expect(fs.existsSync(path.join(vault, "safe-id.b64"))).toBe(false);
  }
});
