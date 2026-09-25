/* eslint-disable no-underscore-dangle -- Existing test-only native adapter injection/reset APIs. */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  CompositeKeyring,
  FileKeyring,
  getDefaultKeyringFromEnv,
  OsKeyring,
  resetDefaultKeyringCache,
} from "./keyring-provider.js";
import { unwrapSecret, wrapSecret } from "./secret-wrapping.js";

const dirs: string[] = [];
function configured(byte: number): NodeJS.ProcessEnv {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "keyring-isolation-"));
  dirs.push(dir);
  const keyPath = path.join(dir, "key");
  fs.writeFileSync(keyPath, Buffer.alloc(32, byte).toString("base64url"), { mode: 0o600 });
  return { OPENCLAW_WRAP_KEY_FILE: keyPath };
}
afterEach(() => {
  resetDefaultKeyringCache();
  OsKeyring.__resetNapiCacheForTests();
  for (const dir of dirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

it("isolates environment objects and releases replaced cached material", () => {
  const a = configured(1),
    b = configured(2);
  const first = getDefaultKeyringFromEnv(a)!;
  const borrowed = first.getActiveKey().key;
  expect(getDefaultKeyringFromEnv(a)).toBe(first);
  expect(getDefaultKeyringFromEnv(b)!.getActiveKey().key).toEqual(Buffer.alloc(32, 2));
  expect(borrowed).toEqual(Buffer.alloc(32));
  expect(getDefaultKeyringFromEnv(a)!.getActiveKey().key).toEqual(Buffer.alloc(32, 1));
  expect(first.getActiveKey().key).toEqual(Buffer.alloc(32, 1));
  first.release?.();
});

it("reevaluates absent and mutated configurations without a manual reset", () => {
  const env: NodeJS.ProcessEnv = {};
  expect(getDefaultKeyringFromEnv(env)).toBeNull();
  Object.assign(env, configured(3));
  expect(getDefaultKeyringFromEnv(env)!.getActiveKey().key).toEqual(Buffer.alloc(32, 3));
  Object.assign(env, configured(4), { OPENCLAW_WRAP_KEY_ID: "changed" });
  expect(getDefaultKeyringFromEnv(env)!.getActiveKey()).toEqual({
    key: Buffer.alloc(32, 4),
    keyId: "changed",
  });
  env.OPENCLAW_WRAP_KEY_FILE = "relative";
  expect(() => getDefaultKeyringFromEnv(env)).toThrow(/absolute/);
});

it.each([
  "OPENCLAW_WRAP_KEY_OS_SERVICE",
  "OPENCLAW_WRAP_KEY_OS_ACCOUNT",
  "OPENCLAW_WRAP_KEY_OS_ID",
])("rejects partial OS configuration %s even after caching a valid file", (field) => {
  const env = configured(5);
  getDefaultKeyringFromEnv(env);
  env[field] = "configured";
  expect(() => getDefaultKeyringFromEnv(env)).toThrow(/together/);
});

it("does not bypass a failed primary for active or historical keys", () => {
  const fallback = new FileKeyring(configured(6).OPENCLAW_WRAP_KEY_FILE!, "historical");
  const failure = new Error("provider unavailable");
  const ring = new CompositeKeyring([
    {
      getActiveKey() {
        throw failure;
      },
      getKeyById() {
        throw failure;
      },
    },
    fallback,
  ]);
  expect(() => ring.getActiveKey()).toThrow(failure);
  expect(() => ring.getKeyById("historical")).toThrow(failure);
  ring.release();
});

it("preserves historical nonownership traversal", () => {
  const primary = new FileKeyring(configured(7).OPENCLAW_WRAP_KEY_FILE!, "primary");
  const historical = new FileKeyring(configured(8).OPENCLAW_WRAP_KEY_FILE!, "historical");
  const ring = new CompositeKeyring([primary, historical]);
  expect(ring.getActiveKey().key).toEqual(Buffer.alloc(32, 7));
  expect(ring.getKeyById("historical")).toEqual(Buffer.alloc(32, 8));
  expect(ring.getKeyById("unknown")).toBeNull();
  ring.release();
});

it("cannot decrypt another environment's envelope even with the same logical ID", () => {
  const a = configured(10),
    b = configured(11);
  const wrapped = wrapSecret(Buffer.from("isolated fixture"), getDefaultKeyringFromEnv(a)!);
  expect(() => unwrapSecret(wrapped, getDefaultKeyringFromEnv(b)!)).toThrow();
  const restored = unwrapSecret(wrapped, getDefaultKeyringFromEnv(a)!);
  expect(restored.toString()).toBe("isolated fixture");
  restored.fill(0);
});

it("refreshes OS service/account/logical ID configuration without reset", () => {
  OsKeyring.__setNapiModuleForTests({
    Entry: class {
      getPassword() {
        return Buffer.alloc(32, 12).toString("base64url");
      }
    },
  });
  const env = {
    OPENCLAW_WRAP_KEY_OS_SERVICE: "one",
    OPENCLAW_WRAP_KEY_OS_ACCOUNT: "one",
    OPENCLAW_WRAP_KEY_OS_ID: "one",
  };
  for (const field of [
    "OPENCLAW_WRAP_KEY_OS_SERVICE",
    "OPENCLAW_WRAP_KEY_OS_ACCOUNT",
    "OPENCLAW_WRAP_KEY_OS_ID",
  ] as const) {
    const before = getDefaultKeyringFromEnv(env)!;
    const borrowed = before.getActiveKey().key;
    env[field] = "two";
    const after = getDefaultKeyringFromEnv(env)! as OsKeyring;
    expect(after).not.toBe(before);
    expect(after.describe()).toEqual({
      service: env.OPENCLAW_WRAP_KEY_OS_SERVICE,
      account: env.OPENCLAW_WRAP_KEY_OS_ACCOUNT,
      keyId: env.OPENCLAW_WRAP_KEY_OS_ID,
    });
    expect(borrowed).toEqual(Buffer.alloc(32));
  }
});

it("invalidates successful OS updates but reports unconfirmed deletion", () => {
  let password: string | null = Buffer.alloc(32, 13).toString("base64url");
  OsKeyring.__setNapiModuleForTests({
    Entry: class {
      getPassword() {
        return password;
      }
      setPassword(next: string) {
        password = next;
      }
      deletePassword() {
        return false;
      }
    },
  });
  const ring = new OsKeyring("service", "account");
  const borrowed = ring.getActiveKey().key;
  ring.setKeyBase64Url(Buffer.alloc(32, 14).toString("base64url"));
  expect(borrowed).toEqual(Buffer.alloc(32));
  expect(ring.getActiveKey().key).toEqual(Buffer.alloc(32, 14));
  expect(() => ring.deleteKey()).toThrow(/did not confirm/);
  ring.release();
});

it.each([null, "malformed", new Error("access denied")])(
  "fails closed for an owning OS entry returning %s",
  (result) => {
    OsKeyring.__setNapiModuleForTests({
      Entry: class {
        getPassword() {
          if (result instanceof Error) {
            throw result;
          }
          return result;
        }
      },
    });
    const primary = new OsKeyring("service", "account", "shared-id");
    const fallback = new FileKeyring(configured(9).OPENCLAW_WRAP_KEY_FILE!, "shared-id");
    const ring = new CompositeKeyring([primary, fallback]);
    expect(primary.getKeyById("unrelated")).toBeNull();
    expect(() => ring.getActiveKey()).toThrow();
    expect(() => ring.getKeyById("shared-id")).toThrow();
    ring.release();
  },
);
