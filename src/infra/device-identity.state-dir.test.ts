// Covers default device identity SQLite path under the state dir.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveGatewayLockDir } from "../config/paths.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { withStateDirEnv } from "../test-helpers/state-dir-env.js";
import { withTempDir } from "../test-utils/temp-dir.js";
import { loadDeviceIdentityIfPresent, loadOrCreateDeviceIdentity } from "./device-identity.js";

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
  vi.restoreAllMocks();
});

describe("device identity state dir defaults", () => {
  it("writes the default identity to the shared state database", async () => {
    await withStateDirEnv("openclaw-identity-state-", async ({ stateDir }) => {
      const identity = loadOrCreateDeviceIdentity();
      const databasePath = path.join(stateDir, "state", "openclaw.sqlite");
      const lockDir = resolveGatewayLockDir(stateDir);

      expect(loadDeviceIdentityIfPresent()).toEqual(identity);
      expect(fs.existsSync(databasePath)).toBe(true);
      expect(fs.readdirSync(lockDir)).toContainEqual(
        expect.stringMatching(/^device-identity\.[0-9a-f]{8}\.lock\.sqlite$/u),
      );
      expect(fs.existsSync(path.join(stateDir, "identity", "device.json"))).toBe(false);
    });
  });

  it("reuses the stored identity on subsequent loads", async () => {
    await withStateDirEnv("openclaw-identity-state-", async () => {
      const first = loadOrCreateDeviceIdentity();
      const second = loadOrCreateDeviceIdentity();

      expect(second).toEqual(first);
    });
  });

  it.each([false, true])(
    "uses the custom database's state owner for both key and coordinator (alias: %s)",
    async (useAlias) => {
      await withStateDirEnv("openclaw-identity-custom-state-", async ({ stateDir }) => {
        const physicalStateDir = path.join(stateDir, "custom-state");
        fs.mkdirSync(physicalStateDir);
        const selectedStateDir = useAlias ? path.join(stateDir, "state-alias") : physicalStateDir;
        if (useAlias) {
          fs.symlinkSync(physicalStateDir, selectedStateDir, "dir");
        }
        const options = { path: path.join(selectedStateDir, "state", "custom.sqlite") };

        const identity = loadOrCreateDeviceIdentity(options);

        expect(loadDeviceIdentityIfPresent(options)).toEqual(identity);
        expect(fs.existsSync(path.join(selectedStateDir, "wrap-key.b64"))).toBe(true);
        expect(fs.existsSync(path.join(stateDir, "wrap-key.b64"))).toBe(false);
        expect(fs.existsSync(resolveGatewayLockDir(selectedStateDir))).toBe(true);
        const pathHash = crypto
          .createHash("sha256")
          .update(fs.realpathSync(options.path))
          .digest("hex")
          .slice(0, 8);
        expect(fs.readdirSync(resolveGatewayLockDir(selectedStateDir))).toEqual([
          `device-identity.${pathHash}.lock.sqlite`,
        ]);
        expect(
          loadDeviceIdentityIfPresent({
            path: path.join(physicalStateDir, "state", "custom.sqlite"),
          }),
        ).toEqual(identity);
        expect(fs.existsSync(resolveGatewayLockDir(stateDir))).toBe(false);
      });
    },
  );

  it("keeps an explicit state owner when the database is elsewhere", async () => {
    await withStateDirEnv("openclaw-identity-explicit-owner-", async ({ stateDir }) => {
      const selectedStateDir = path.join(stateDir, "selected-state");
      const databaseStateDir = path.join(stateDir, "database-state");
      const identity = loadOrCreateDeviceIdentity({
        env: { ...process.env, OPENCLAW_STATE_DIR: selectedStateDir },
        path: path.join(databaseStateDir, "state", "custom.sqlite"),
      });

      expect(identity.deviceId).toBeTruthy();
      expect(fs.existsSync(path.join(selectedStateDir, "wrap-key.b64"))).toBe(true);
      expect(fs.existsSync(resolveGatewayLockDir(selectedStateDir))).toBe(true);
      expect(fs.existsSync(path.join(databaseStateDir, "wrap-key.b64"))).toBe(false);
      expect(fs.existsSync(resolveGatewayLockDir(databaseStateDir))).toBe(false);
      expect(fs.existsSync(resolveGatewayLockDir(stateDir))).toBe(false);
    });
  });

  it("uses the supplied state environment for its coordinator", async () => {
    await withTempDir("openclaw-identity-env-state-", async (rootDir) => {
      const stateDir = path.join(rootDir, "selected-state");
      const fakeHome = path.join(rootDir, "home");
      const legacyTmpDir = path.join(rootDir, "legacy-process-tmp");
      fs.mkdirSync(stateDir, { recursive: true });
      fs.mkdirSync(fakeHome, { recursive: true });
      fs.mkdirSync(legacyTmpDir, { recursive: true });
      vi.spyOn(os, "tmpdir").mockReturnValue(legacyTmpDir);
      const env = {
        ...process.env,
        HOME: fakeHome,
        OPENCLAW_HOME: fakeHome,
        OPENCLAW_STATE_DIR: stateDir,
      };

      loadOrCreateDeviceIdentity({ env });

      expect(fs.readdirSync(resolveGatewayLockDir(stateDir))).toContainEqual(
        expect.stringMatching(/^device-identity\.[0-9a-f]{8}\.lock\.sqlite$/u),
      );
      expect(fs.readdirSync(legacyTmpDir)).toEqual([]);
      expect(fs.existsSync(path.join(fakeHome, ".openclaw"))).toBe(false);
    });
  });

  it("keeps read-only lookup non-creating when the default database is absent", async () => {
    await withStateDirEnv("openclaw-identity-state-", async ({ stateDir }) => {
      const databasePath = path.join(stateDir, "state", "openclaw.sqlite");

      expect(loadDeviceIdentityIfPresent()).toBeNull();
      expect(fs.existsSync(databasePath)).toBe(false);
    });
  });
});
