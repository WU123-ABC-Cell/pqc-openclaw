import fs from "node:fs/promises";
import path from "node:path";
import * as tar from "tar";
import { describe, expect, it } from "vitest";
import { backupVerifyCommand } from "../commands/backup-verify.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";
import { withOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { createBackupArchive } from "./backup-create.js";
import { createBackupWrappingKeyFilter } from "./backup-wrapping-key-filter.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentityReadOnly,
} from "./device-identity-store.js";

async function listEntries(file: string): Promise<string[]> {
  const entries: string[] = [];
  await tar.t({
    file,
    onentry: (entry) => {
      entries.push(entry.path);
      entry.resume();
    },
  });
  return entries;
}

describe("backup wrapping-key exclusion", () => {
  it("rejects a whole-file asset that is also the configured wrapping key", async () => {
    await withOpenClawTestState({ env: { OPENCLAW_WRAP_KEY_FILE: undefined } }, async (state) => {
      await state.writeConfig({});
      process.env.OPENCLAW_WRAP_KEY_FILE = state.configPath;
      const output = state.path("backup.tar.gz");
      await expect(createBackupArchive({ output, onlyConfig: true })).rejects.toThrow(
        "overlaps a wrapping key",
      );
      await expect(fs.stat(output)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(createBackupArchive({ output, onlyConfig: true, dryRun: true })).rejects.toThrow(
        "overlaps a wrapping key",
      );
    });
  });

  it("fails before archive publication when protected metadata is not a file", async () => {
    await withOpenClawTestState({ env: { OPENCLAW_WRAP_KEY_FILE: undefined } }, async (state) => {
      await fs.mkdir(state.statePath("wrap-key.b64"));
      const output = state.path("backup.tar.gz");
      await expect(createBackupArchive({ output })).rejects.toThrow(
        "Wrapping key must be a regular file",
      );
      await expect(fs.stat(output)).rejects.toMatchObject({ code: "ENOENT" });
    });
  });

  it("detects changed, replaced, and newly appearing keys", async () => {
    await withOpenClawTestState({ env: { OPENCLAW_WRAP_KEY_FILE: undefined } }, async (state) => {
      const key = state.statePath("wrap-key.b64");
      const missing = await createBackupWrappingKeyFilter(state.stateDir);
      await missing.assertUnchanged();
      await fs.writeFile(key, "old");
      await expect(missing.assertUnchanged()).rejects.toThrow("changed during backup");
      const previous = await createBackupWrappingKeyFilter(state.stateDir);
      await fs.writeFile(key, "changed-size");
      await expect(previous.assertUnchanged()).rejects.toThrow("changed during backup");
      const replaced = await createBackupWrappingKeyFilter(state.stateDir);
      await fs.rename(key, state.path("old-key"));
      await fs.writeFile(key, "replacement");
      await expect(replaced.assertUnchanged()).rejects.toThrow("changed during backup");
    });
  });

  it.each([false, true])("excludes default key and hardlinks (custom=%s)", async (custom) => {
    await withOpenClawTestState({ env: { OPENCLAW_WRAP_KEY_FILE: undefined } }, async (state) => {
      const defaultKey = path.join(state.stateDir, "wrap-key.b64");
      const key = custom ? path.join(state.root, "external-key") : defaultKey;
      await fs.writeFile(defaultKey, "default-secret", { mode: 0o600 });
      if (custom) {
        await fs.writeFile(key, "custom-secret", { mode: 0o600 });
        process.env.OPENCLAW_WRAP_KEY_FILE = key;
      }
      await fs.link(key, path.join(state.stateDir, "innocent.txt"));
      await fs.writeFile(path.join(state.stateDir, "ordinary.b64"), "ordinary-data");
      const result = await createBackupArchive({ output: path.join(state.root, "backup.tar.gz") });
      const entries = await listEntries(result.archivePath);
      expect(entries.some((entry) => entry.endsWith("/wrap-key.b64"))).toBe(false);
      expect(entries.some((entry) => entry.endsWith("/innocent.txt"))).toBe(false);
      expect(entries.some((entry) => entry.endsWith("/ordinary.b64"))).toBe(true);
    });
  });

  it("retains a wrapped identity restorable only with independently supplied key", async () => {
    await withOpenClawTestState({ env: { OPENCLAW_WRAP_KEY_FILE: undefined } }, async (state) => {
      const key = Buffer.alloc(32, 0x37);
      const provider = {
        getActiveKey: () => ({ key, keyId: "fixture" }),
        getKeyById: (id: string) => (id === "fixture" ? key : null),
      };
      await fs.writeFile(state.statePath("wrap-key.b64"), key.toString("base64"), { mode: 0o600 });
      const identity = insertStoredDeviceIdentityIfAbsent(
        generateStoredDeviceIdentity(1, provider),
        {
          env: state.env,
          wrappingKeyProvider: provider,
        },
      );
      const result = await createBackupArchive({ output: state.path("backup.tar.gz") });
      const runtime = { log: () => {}, error: () => {}, exit: () => {} };
      const verified = await backupVerifyCommand(runtime, { archive: result.archivePath });
      expect(verified.ok).toBe(true);
      const restoreDir = state.path("restore");
      await fs.mkdir(restoreDir);
      await tar.x({ file: result.archivePath, cwd: restoreDir });
      const entries = await listEntries(result.archivePath);
      const dbName = path.basename(resolveOpenClawStateSqlitePath(state.env));
      const dbEntry = entries.find((entry) => entry.endsWith(`/${dbName}`));
      expect(dbEntry).toBeDefined();
      const restoredPath = path.join(restoreDir, dbEntry!);
      const restored = readStoredDeviceIdentityReadOnly({
        path: restoredPath,
        wrappingKeyProvider: provider,
      });
      expect(restored?.deviceId).toBe(identity.deviceId);
      expect(restored?.privateKeyPem).toBe(identity.privateKeyPem);
      expect(() => readStoredDeviceIdentityReadOnly({ path: restoredPath })).toThrow();
      expect(entries.some((entry) => entry.endsWith("/wrap-key.b64"))).toBe(false);
    });
  });

  it("excludes canonical targets of configured symlinks and SQLite-named hardlinks", async () => {
    await withOpenClawTestState({ env: { OPENCLAW_WRAP_KEY_FILE: undefined } }, async (state) => {
      const target = state.statePath("target.sqlite");
      const link = state.path("key-link");
      await fs.writeFile(target, "secret", { mode: 0o600 });
      await fs.symlink(target, link);
      await fs.link(target, state.statePath("alias.sqlite"));
      process.env.OPENCLAW_WRAP_KEY_FILE = link;
      const result = await createBackupArchive({ output: state.path("backup.tar.gz") });
      const entries = await listEntries(result.archivePath);
      expect(
        entries.some(
          (entry) => entry.endsWith("/target.sqlite") || entry.endsWith("/alias.sqlite"),
        ),
      ).toBe(false);
    });
  });

  it("excludes keys when a workspace ancestor covers the state asset", async () => {
    await withOpenClawTestState(
      { layout: "state-only", env: { OPENCLAW_WRAP_KEY_FILE: undefined } },
      async (state) => {
        await state.writeConfig({ agents: { defaults: { workspace: state.root } } });
        const key = state.statePath("wrap-key.b64");
        await fs.writeFile(key, "secret", { mode: 0o600 });
        await fs.link(key, state.path("workspace-key-alias"));
        // The output cannot be inside the workspace being archived.
        const output = `${state.root}-backup.tar.gz`;
        try {
          const result = await createBackupArchive({ output });
          expect(result.assets.some((asset) => asset.kind === "state")).toBe(false);
          const entries = await listEntries(result.archivePath);
          expect(
            entries.some(
              (entry) => entry.endsWith("/wrap-key.b64") || entry.endsWith("/workspace-key-alias"),
            ),
          ).toBe(false);
        } finally {
          await fs.rm(output, { force: true });
        }
      },
    );
  });
});
