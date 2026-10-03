import fs from "node:fs";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PRIMARY_DEVICE_IDENTITY_KEY } from "../infra/device-identity-store.js";
import { loadOrCreateDeviceIdentity } from "../infra/device-identity.js";
import { defaultRuntime } from "../runtime.js";
import { resetDefaultKeyringCache } from "../security/keyring-provider.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { withStateDirEnv } from "../test-helpers/state-dir-env.js";
import { resolveCliCommandPathPolicy } from "./command-path-policy.js";
import { registerSubCliByName, registerSubCliCommands } from "./program/register.subclis.js";

beforeEach(() => {
  for (const name of [
    "OPENCLAW_WRAP_KEY_FILE",
    "OPENCLAW_WRAP_KEY_ID",
    "OPENCLAW_WRAP_KEY_OS_SERVICE",
    "OPENCLAW_WRAP_KEY_OS_ACCOUNT",
    "OPENCLAW_WRAP_KEY_OS_ID",
  ]) {
    vi.stubEnv(name, undefined);
  }
  resetDefaultKeyringCache();
});

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
  resetDefaultKeyringCache();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

async function runWrapKey(args: string[], writeOut: (text: string) => void = () => undefined) {
  const argv = ["node", "openclaw", "wrap-key", ...args];
  const program = new Command().name("openclaw").exitOverride();
  program.configureOutput({ writeOut, writeErr: () => undefined });
  registerSubCliCommands(program, argv);
  // The CLI entry eagerly resolves the named registrar for command-specific
  // help; otherwise Commander only sees the root's lazy placeholder.
  if (args.includes("--help")) {
    expect(await registerSubCliByName(program, "wrap-key", argv)).toBe(true);
  }
  await program.parseAsync(argv);
  return program;
}

describe("wrap-key operator boundary", () => {
  it("keeps status off startup paths that can mutate state", () => {
    expect(resolveCliCommandPathPolicy(["wrap-key", "status"])).toMatchObject({
      configGuard: "skip",
      loadPlugins: "never",
      ensureCliPath: false,
      networkProxy: "bypass",
    });
  });

  it("registers lazy help without creating state and rejects unavailable mutations", async () => {
    await withStateDirEnv("wrap-key-help-", async ({ stateDir }) => {
      const help = vi.fn();
      await expect(runWrapKey(["status", "--help"], help)).rejects.toMatchObject({
        code: "commander.helpDisplayed",
      });
      expect(help.mock.calls.flat().join("")).toContain("--identity-key <key>");
      for (const command of ["import", "export", "rotate"]) {
        await expect(runWrapKey([command])).rejects.toMatchObject({
          exitCode: 1,
        });
      }
      expect(fs.readdirSync(stateDir)).toEqual([]);
    });
  });

  it("reports missing identity/key as unhealthy without creating either", async () => {
    await withStateDirEnv("wrap-key-empty-", async ({ stateDir }) => {
      const output = vi.spyOn(defaultRuntime, "writeJson").mockImplementation(() => undefined);
      const exit = vi.spyOn(defaultRuntime, "exit").mockImplementation(() => undefined);
      await runWrapKey(["status", "--json"]);
      expect(output).toHaveBeenCalledWith(
        expect.objectContaining({ ok: false, identityKeys: [PRIMARY_DEVICE_IDENTITY_KEY] }),
      );
      expect(exit).toHaveBeenCalledWith(1, { resetStream: process.stderr });
      expect(fs.readdirSync(stateDir)).toEqual([]);
    });
  });

  it("checks the actual persisted identity and does not write or generate a fallback key", async () => {
    await withStateDirEnv("wrap-key-existing-", async ({ stateDir }) => {
      const identity = loadOrCreateDeviceIdentity();
      closeOpenClawStateDatabaseForTest();
      const dbPath = path.join(stateDir, "state", "openclaw.sqlite");
      const keyPath = path.join(stateDir, "wrap-key.b64");
      const before = { database: fs.readFileSync(dbPath), key: fs.readFileSync(keyPath) };
      const sourceFiles = fs.readdirSync(path.dirname(dbPath));
      const write = vi.spyOn(fs, "writeFileSync");
      const mkdir = vi.spyOn(fs, "mkdirSync");
      const output = vi.spyOn(defaultRuntime, "writeJson").mockImplementation(() => undefined);
      const exit = vi.spyOn(defaultRuntime, "exit").mockImplementation(() => undefined);
      await runWrapKey(["status", "--json"]);
      expect(output).toHaveBeenCalledWith(
        expect.objectContaining({
          ok: true,
          rows: [expect.objectContaining({ deviceId: identity.deviceId, state: "wrapped" })],
        }),
      );
      expect(JSON.stringify(output.mock.calls)).not.toContain(identity.privateKeyPem);
      expect(JSON.stringify(output.mock.calls)).not.toContain(before.key.toString());
      expect(write).not.toHaveBeenCalled();
      expect(mkdir).not.toHaveBeenCalled();
      expect({ database: fs.readFileSync(dbPath), key: fs.readFileSync(keyPath) }).toEqual(before);
      // A fresh read-only WAL connection can create SQLite coordination files,
      // but must not create other product state or rewrite the identity/key.
      const addedFiles = fs
        .readdirSync(path.dirname(dbPath))
        .filter((name) => !sourceFiles.includes(name));
      expect(
        addedFiles.every(
          (name) => name === "openclaw.sqlite-wal" || name === "openclaw.sqlite-shm",
        ),
      ).toBe(true);
      expect(exit).not.toHaveBeenCalled();

      output.mockClear();
      await runWrapKey(["status", "--json", "--identity-key", "absent"]);
      expect(output).toHaveBeenCalledWith(
        expect.objectContaining({ ok: false, identityKeys: ["absent"] }),
      );
      expect(exit).toHaveBeenCalledWith(1, { resetStream: process.stderr });
    });
  });

  it("fails closed for damaged rows and incomplete provider configuration", async () => {
    await withStateDirEnv("wrap-key-damaged-", async ({ stateDir }) => {
      loadOrCreateDeviceIdentity();
      closeOpenClawStateDatabaseForTest();
      fs.writeFileSync(path.join(stateDir, "state", "openclaw.sqlite"), "not SQLite");
      const output = vi.spyOn(defaultRuntime, "writeJson").mockImplementation(() => undefined);
      const exit = vi.spyOn(defaultRuntime, "exit").mockImplementation(() => undefined);
      await runWrapKey(["status", "--json"]);
      expect(output).toHaveBeenLastCalledWith(expect.objectContaining({ ok: false }));
      expect(exit).toHaveBeenCalledWith(1, { resetStream: process.stderr });

      vi.stubEnv("OPENCLAW_WRAP_KEY_OS_SERVICE", "not-a-complete-provider");
      await runWrapKey(["status", "--json"]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({ ok: false, error: "wrapping-key-status-unavailable" }),
      );
    });
  });
});
