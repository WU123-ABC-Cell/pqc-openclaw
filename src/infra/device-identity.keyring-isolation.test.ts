import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  FileKeyring,
  resetDefaultKeyringCache,
  type KeyringProvider,
} from "../security/keyring-provider.js";
import { resolveDeviceIdentityWrappingOptions } from "./device-identity.js";

const dirs: string[] = [];
const providers: KeyringProvider[] = [];
function stateDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "identity-keyring-isolation-"));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  resetDefaultKeyringCache();
  for (const provider of providers.splice(0)) {
    provider.release?.();
  }
  for (const dir of dirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

it("selects each state's fallback path without inheriting the previous explicit provider", () => {
  const a = stateDir(),
    b = stateDir();
  const custom = path.join(a, "custom");
  fs.writeFileSync(custom, Buffer.alloc(32, 1).toString("base64url"), { mode: 0o600 });
  const first = resolveDeviceIdentityWrappingOptions(
    { env: { OPENCLAW_STATE_DIR: a, OPENCLAW_WRAP_KEY_FILE: custom } },
    true,
  ).wrappingKeyProvider!;
  expect(first.getActiveKey().key).toEqual(Buffer.alloc(32, 1));
  for (const dir of [b, a]) {
    const provider = resolveDeviceIdentityWrappingOptions(
      { env: { OPENCLAW_STATE_DIR: dir } },
      true,
    ).wrappingKeyProvider! as FileKeyring;
    providers.push(provider);
    expect(provider.getKeyPath()).toBe(path.join(dir, "wrap-key.b64"));
    expect(provider.getActiveKey().key).not.toEqual(Buffer.alloc(32, 1));
  }
});

it("rejects partial OS configuration before creating a fallback key", () => {
  const dir = stateDir();
  expect(() =>
    resolveDeviceIdentityWrappingOptions(
      { env: { OPENCLAW_STATE_DIR: dir, OPENCLAW_WRAP_KEY_OS_SERVICE: "service" } },
      true,
    ),
  ).toThrow(/together/);
  expect(fs.existsSync(path.join(dir, "wrap-key.b64"))).toBe(false);
});
