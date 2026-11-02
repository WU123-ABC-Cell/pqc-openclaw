import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PRIMARY_DEVICE_IDENTITY_KEY } from "../infra/device-identity-store.js";
import { loadOrCreateDeviceIdentity } from "../infra/device-identity.js";
import { defaultRuntime } from "../runtime.js";
import { resetDefaultKeyringCache } from "../security/keyring-provider.js";
import { resolveWrappingKeyVaultPath } from "../security/wrap-key-file-install.js";
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

  it("registers lazy help without creating state and rejects unavailable import/export", async () => {
    await withStateDirEnv("wrap-key-help-", async ({ stateDir }) => {
      const help = vi.fn();
      await expect(runWrapKey(["status", "--help"], help)).rejects.toMatchObject({
        code: "commander.helpDisplayed",
      });
      expect(help.mock.calls.flat().join("")).toContain("--identity-key <key>");
      await expect(runWrapKey(["prepare", "--help"], help)).rejects.toMatchObject({
        code: "commander.helpDisplayed",
      });
      expect(help.mock.calls.flat().join("")).toContain("--key-id <id>");
      for (const command of ["import", "export"]) {
        await expect(runWrapKey([command])).rejects.toMatchObject({
          exitCode: 1,
        });
      }
      expect(fs.readdirSync(stateDir)).toEqual([]);
    });
  });

  it("activates and rotates offline, then reopens every identity with the new persisted key", async () => {
    await withStateDirEnv("wrap-key-offline-", async ({ stateDir }) => {
      const original = loadOrCreateDeviceIdentity();
      closeOpenClawStateDatabaseForTest();
      const oldPath = path.join(stateDir, "wrap-key.b64");
      const oldBytes = fs.readFileSync(oldPath);
      const output = vi.spyOn(defaultRuntime, "writeJson").mockImplementation(() => undefined);
      const exit = vi.spyOn(defaultRuntime, "exit").mockImplementation(() => undefined);

      await runWrapKey(["activate", "--receipt-id", "activate-1", "--json"]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({ ok: false, operation: "activate" }),
      );
      expect(exit).toHaveBeenCalledWith(1, { resetStream: process.stderr });
      exit.mockClear();

      await runWrapKey(["activate", "--receipt-id", "activate-1", "--offline", "--json"]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({ ok: true, databaseState: "current", generation: 1 }),
      );
      fs.renameSync(oldPath, `${oldPath}.held`);
      await runWrapKey(["activate", "--receipt-id", "activate-1", "--offline", "--json"]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({ ok: false, databaseState: "current", generation: 1 }),
      );
      fs.renameSync(`${oldPath}.held`, oldPath);
      exit.mockClear();
      await runWrapKey(["prepare", "--key-id", "key-new", "--json"]);
      const newPath = path.join(resolveWrappingKeyVaultPath(stateDir), "key-new.b64");
      await runWrapKey([
        "rotate",
        "--receipt-id",
        "rotate-2",
        "--key-id",
        "key-new",
        "--offline",
        "--json",
      ]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({
          ok: true,
          operation: "rotate",
          databaseState: "current",
          generation: 2,
          keyId: "key-new",
          allRowsVerified: true,
          checkedRows: 1,
          cliKeySelected: false,
          gatewayRestartUnverified: true,
        }),
      );
      expect(fs.readFileSync(oldPath)).toEqual(oldBytes);
      expect(exit).not.toHaveBeenCalled();

      await runWrapKey([
        "recover",
        "--receipt-id",
        "rotate-2",
        "--key-id",
        "key-new",
        "--offline",
        "--json",
      ]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({
          ok: false,
          operation: "recover",
          databaseState: "current",
          cliKeySelected: false,
          gatewayRestartUnverified: true,
        }),
      );
      expect(exit).toHaveBeenCalledWith(1, { resetStream: process.stderr });
      exit.mockClear();

      vi.stubEnv("OPENCLAW_WRAP_KEY_FILE", newPath);
      vi.stubEnv("OPENCLAW_WRAP_KEY_ID", "key-new");
      resetDefaultKeyringCache();
      closeOpenClawStateDatabaseForTest();
      expect(loadOrCreateDeviceIdentity().deviceId).toBe(original.deviceId);
      closeOpenClawStateDatabaseForTest();
      const restarted = spawnSync(
        process.execPath,
        [
          "--import",
          "tsx",
          "--input-type=module",
          "-e",
          'import { loadDeviceIdentityIfPresent } from "./src/infra/device-identity.ts"; const identity = loadDeviceIdentityIfPresent(); if (!identity) process.exit(2); console.log(identity.deviceId);',
        ],
        { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 30_000 },
      );
      expect(restarted.status, restarted.stderr).toBe(0);
      expect(restarted.stdout.trim()).toBe(original.deviceId);
      await runWrapKey([
        "recover",
        "--receipt-id",
        "rotate-2",
        "--key-id",
        "key-new",
        "--offline",
        "--json",
      ]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({
          ok: true,
          operation: "recover",
          databaseState: "current",
          allRowsVerified: true,
          checkedRows: 1,
          cliKeySelected: true,
          gatewayRestartUnverified: true,
        }),
      );
      expect(exit).not.toHaveBeenCalled();
      fs.renameSync(newPath, `${newPath}.held`);
      await runWrapKey([
        "recover",
        "--receipt-id",
        "rotate-2",
        "--key-id",
        "key-new",
        "--offline",
        "--json",
      ]);
      expect(output).toHaveBeenLastCalledWith(
        expect.objectContaining({ ok: false, databaseState: "current", generation: 2 }),
      );
      fs.renameSync(`${newPath}.held`, newPath);
      exit.mockClear();
      expect(JSON.stringify(output.mock.calls)).not.toContain(oldBytes.toString());
      expect(JSON.stringify(output.mock.calls)).not.toContain(fs.readFileSync(newPath, "utf8"));
    });
  });

  it("prepares a separate key once without switching the active identity", async () => {
    await withStateDirEnv("wrap-key-prepare-", async ({ stateDir }) => {
      const original = loadOrCreateDeviceIdentity();
      closeOpenClawStateDatabaseForTest();
      const oldPath = path.join(stateDir, "wrap-key.b64");
      const oldKey = fs.readFileSync(oldPath);
      const output = vi.spyOn(defaultRuntime, "writeJson").mockImplementation(() => undefined);
      const exit = vi.spyOn(defaultRuntime, "exit").mockImplementation(() => undefined);
      await runWrapKey(["prepare", "--key-id", "key-new", "--json"]);
      const keyPath = path.join(resolveWrappingKeyVaultPath(stateDir), "key-new.b64");
      expect(output).toHaveBeenLastCalledWith({
        ok: true,
        keyId: "key-new",
        keyPath,
        active: false,
      });
      expect(fs.readFileSync(oldPath)).toEqual(oldKey);
      expect(loadOrCreateDeviceIdentity().deviceId).toBe(original.deviceId);
      expect(JSON.stringify(output.mock.calls)).not.toContain(oldKey.toString());
      expect(JSON.stringify(output.mock.calls)).not.toContain(fs.readFileSync(keyPath, "utf8"));
      expect(exit).not.toHaveBeenCalled();
      await runWrapKey(["prepare", "--key-id", "key-new", "--json"]);
      expect(output).toHaveBeenLastCalledWith({ ok: false, error: "wrapping-key-prepare-failed" });
      expect(exit).toHaveBeenCalledWith(1, { resetStream: process.stderr });
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
