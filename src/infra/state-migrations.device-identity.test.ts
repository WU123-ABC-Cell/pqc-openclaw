// Active regression coverage for retiring legacy Ed25519 identities into ML-DSA-only state.
import crypto, { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { __setFsSafeTestHooksForTest } from "@openclaw/fs-safe/test-hooks";
import { afterEach, expect, it, vi } from "vitest";
import { FileKeyring, resetDefaultKeyringCache } from "../security/keyring-provider.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import { loadDeviceAuthToken, storeDeviceAuthToken } from "./device-auth-store.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
} from "./device-identity-store.js";
import { requireNodeSqlite } from "./node-sqlite.js";
import {
  detectLegacyDeviceIdentity,
  migrateLegacyDeviceIdentity,
} from "./state-migrations.device-identity.js";

const archiveFault = vi.hoisted(() => ({
  operation: "" as "" | "open" | "chmod" | "sync" | "read" | "remove",
  fired: false,
  beforeRead: undefined as (() => void) | undefined,
  beforeCreate: undefined as (() => void) | undefined,
  beforeTargetCreate: undefined as { path: string; run: () => void } | undefined,
  beforePublishTarget: undefined as { path: string; run: () => void } | undefined,
  directorySyncFailure: false,
}));

vi.mock("./directory-durability.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./directory-durability.js")>();
  return {
    ...actual,
    publishFileNoClobber: async (...args: Parameters<typeof actual.publishFileNoClobber>) => {
      if (args[1] === archiveFault.beforePublishTarget?.path) {
        const injected = archiveFault.beforePublishTarget;
        archiveFault.beforePublishTarget = undefined;
        archiveFault.beforeTargetCreate = undefined;
        injected.run();
      }
      return await actual.publishFileNoClobber(...args);
    },
    syncDirectoryIfSupported: async (
      ...args: Parameters<typeof actual.syncDirectoryIfSupported>
    ) => {
      if (
        archiveFault.directorySyncFailure &&
        path.basename(args[0]) === "identity" &&
        fs.existsSync(path.join(args[0], "device.json.migrated"))
      ) {
        archiveFault.directorySyncFailure = false;
        throw new Error("injected archive directory sync failure");
      }
      return await actual.syncDirectoryIfSupported(...args);
    },
  };
});

vi.mock("@openclaw/fs-safe", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@openclaw/fs-safe")>();
  return {
    ...actual,
    root: async (...args: Parameters<typeof actual.root>) => {
      const stateRoot = await actual.root(...args);
      const open = stateRoot.open.bind(stateRoot);
      const read = stateRoot.read.bind(stateRoot);
      const remove = stateRoot.remove.bind(stateRoot);
      const create = stateRoot.create.bind(stateRoot);
      stateRoot.create = async (...createArgs: Parameters<typeof stateRoot.create>) => {
        if (createArgs[0] === archiveFault.beforeTargetCreate?.path) {
          const injected = archiveFault.beforeTargetCreate;
          archiveFault.beforeTargetCreate = undefined;
          injected.run();
        }
        if (createArgs[0].endsWith("device.json.migrated")) {
          const beforeCreate = archiveFault.beforeCreate;
          archiveFault.beforeCreate = undefined;
          beforeCreate?.();
        }
        return await create(...createArgs);
      };
      stateRoot.open = async (...openArgs: Parameters<typeof stateRoot.open>) => {
        if (
          openArgs[0].endsWith("device.json.migrated") &&
          archiveFault.operation === "open" &&
          !archiveFault.fired
        ) {
          archiveFault.fired = true;
          throw new Error("injected archive open failure");
        }
        const opened = await open(...openArgs);
        if (
          openArgs[0].endsWith("device.json.migrated") &&
          archiveFault.operation === "chmod" &&
          !archiveFault.fired
        ) {
          archiveFault.fired = true;
          vi.spyOn(opened.handle, "chmod").mockRejectedValueOnce(
            new Error("injected archive chmod failure"),
          );
        }
        if (
          openArgs[0].endsWith("device.json.migrated") &&
          archiveFault.operation === "sync" &&
          !archiveFault.fired
        ) {
          archiveFault.fired = true;
          vi.spyOn(opened.handle, "sync").mockRejectedValueOnce(
            new Error("injected archive sync failure"),
          );
        }
        return opened;
      };
      stateRoot.read = async (...readArgs: Parameters<typeof stateRoot.read>) => {
        if (readArgs[0].endsWith("device.json.migrated")) {
          const beforeRead = archiveFault.beforeRead;
          archiveFault.beforeRead = undefined;
          beforeRead?.();
          if (archiveFault.operation === "read" && !archiveFault.fired) {
            archiveFault.fired = true;
            throw new Error("injected archive read failure");
          }
        }
        return await read(...readArgs);
      };
      stateRoot.remove = async (...removeArgs: Parameters<typeof stateRoot.remove>) => {
        if (
          removeArgs[0].endsWith("device.json.doctor-importing") &&
          archiveFault.operation === "remove" &&
          !archiveFault.fired
        ) {
          archiveFault.fired = true;
          throw new Error("injected archive remove failure");
        }
        return await remove(...removeArgs);
      };
      return stateRoot;
    },
  };
});

const dirs: string[] = [];
const providers: FileKeyring[] = [];

function fixture() {
  const stateDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "legacy-pqc-identity-")));
  dirs.push(stateDir);
  const keyPath = path.join(stateDir, "wrap-key.b64");
  fs.writeFileSync(keyPath, Buffer.alloc(32, 23).toString("base64url"), { mode: 0o600 });
  const env = {
    ...process.env,
    HOME: stateDir,
    OPENCLAW_STATE_DIR: stateDir,
    OPENCLAW_WRAP_KEY_FILE: keyPath,
    OPENCLAW_WRAP_KEY_ID: "legacy-migration-test",
  };
  const provider = new FileKeyring(keyPath, "legacy-migration-test");
  providers.push(provider);
  return { env, provider, stateDir };
}

function legacyNodeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const publicKeyRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return {
    deviceId: createHash("sha256").update(publicKeyRaw).digest("hex"),
    value: {
      version: 1,
      deviceId: "stale-device-id",
      publicKeyPem,
      privateKeyPem,
      createdAtMs: 1_700_000_000_000,
    },
  };
}

function writeLegacy(stateDir: string, value: unknown): { bytes: Buffer; path: string } {
  const sourcePath = path.join(stateDir, "identity", "device.json");
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  fs.mkdirSync(path.dirname(sourcePath), { recursive: true });
  fs.writeFileSync(sourcePath, bytes, { mode: 0o644 });
  return { bytes, path: sourcePath };
}

async function migrate(stateDir: string, env: NodeJS.ProcessEnv) {
  return await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({
      stateDir,
      env,
      doctorOnlyStateMigrations: true,
    }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
  });
}

afterEach(() => {
  __setFsSafeTestHooksForTest(undefined);
  vi.restoreAllMocks();
  archiveFault.operation = "";
  archiveFault.fired = false;
  archiveFault.beforeRead = undefined;
  archiveFault.beforeCreate = undefined;
  archiveFault.beforeTargetCreate = undefined;
  archiveFault.beforePublishTarget = undefined;
  archiveFault.directorySyncFailure = false;
  closeOpenClawStateDatabaseForTest();
  resetDefaultKeyringCache();
  for (const provider of providers.splice(0)) {
    provider.release();
  }
  for (const dir of dirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

it("retires a valid Ed25519 identity without transferring authorization", async () => {
  const { env, provider, stateDir } = fixture();
  const legacy = legacyNodeIdentity();
  const source = writeLegacy(stateDir, legacy.value);
  const result = await migrate(stateDir, env);

  const stored = readStoredDeviceIdentity({
    env,
    identityKey: "primary",
    wrappingKeyProvider: provider,
  });
  const archivePath = `${source.path}.migrated`;
  expect(result.warnings).toEqual([]);
  expect(result.notices).toContain(
    "The retired Ed25519 device authorization was not transferred; approve the new ML-DSA device identity.",
  );
  expect(stored?.deviceId).toMatch(/^[a-f0-9]{64}$/);
  expect(stored?.deviceId).not.toBe(legacy.deviceId);
  expect(fs.existsSync(source.path)).toBe(false);
  expect(fs.readFileSync(archivePath)).toEqual(source.bytes);
  expect(fs.statSync(archivePath).mode & 0o777).toBe(0o600);
});

it("does nothing without explicit migration authority", async () => {
  const { env, provider, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);

  const result = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env }),
    stateDir,
    env,
  });

  expect(result).toEqual({ changes: [], warnings: [] });
  expect(fs.existsSync(source.path)).toBe(true);
  expect(
    readStoredDeviceIdentity({ env, identityKey: "primary", wrappingKeyProvider: provider }),
  ).toBeNull();
});

it("does not create state when Doctor has no legacy identity or pending receipt", async () => {
  const { env, stateDir } = fixture();
  expect(await migrate(stateDir, env)).toEqual({ changes: [], warnings: [] });
  expect(fs.existsSync(path.join(stateDir, "state", "openclaw.sqlite"))).toBe(false);
});

it("rejects a mixed Ed25519 keypair and preserves the source", async () => {
  const { env, provider, stateDir } = fixture();
  const publicIdentity = legacyNodeIdentity();
  const privateIdentity = legacyNodeIdentity();
  const source = writeLegacy(stateDir, {
    ...publicIdentity.value,
    privateKeyPem: privateIdentity.value.privateKeyPem,
  });

  const result = await migrate(stateDir, env);

  expect(result.warnings.join("\n")).toContain("invalid or unsupported");
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(fs.existsSync(`${source.path}.migrated`)).toBe(false);
  expect(
    readStoredDeviceIdentity({ env, identityKey: "primary", wrappingKeyProvider: provider }),
  ).toBeNull();
});

it("rejects an object that mixes Node and Swift legacy identity fields", async () => {
  const { env, provider, stateDir } = fixture();
  const legacy = legacyNodeIdentity();
  const source = writeLegacy(stateDir, {
    ...legacy.value,
    publicKey: Buffer.alloc(32, 1).toString("base64url"),
    privateKey: Buffer.alloc(32, 2).toString("base64url"),
  });

  const result = await migrate(stateDir, env);

  expect(result.warnings.join("\n")).toContain("invalid or unsupported");
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(
    readStoredDeviceIdentity({ env, identityKey: "primary", wrappingKeyProvider: provider }),
  ).toBeNull();
});

it("preserves an existing valid ML-DSA identity while retiring stale Ed25519 state", async () => {
  const { env, provider, stateDir } = fixture();
  const existing = insertStoredDeviceIdentityIfAbsent(
    generateStoredDeviceIdentity(1_700_000_000_001, provider),
    { env, identityKey: "primary", wrappingKeyProvider: provider },
  );
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);

  const result = await migrate(stateDir, env);
  const stored = readStoredDeviceIdentity({
    env,
    identityKey: "primary",
    wrappingKeyProvider: provider,
  });

  expect(result.warnings).toEqual([]);
  expect(result.changes).toContain("Preserved the existing ML-DSA primary device identity.");
  expect(stored?.deviceId).toBe(existing.deviceId);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
});

it("rewraps an existing plaintext ML-DSA identity before retiring Ed25519 state", async () => {
  const { env, provider, stateDir } = fixture();
  const existing = insertStoredDeviceIdentityIfAbsent(
    generateStoredDeviceIdentity(1_700_000_000_003, undefined, {
      allowPlaintextPrivateKey: true,
    }),
    { env, identityKey: "primary" },
  );
  writeLegacy(stateDir, legacyNodeIdentity().value);

  const result = await migrate(stateDir, env);

  expect(result.warnings).toEqual([]);
  expect(
    readStoredDeviceIdentity({ env, identityKey: "primary", wrappingKeyProvider: provider })
      ?.deviceId,
  ).toBe(existing.deviceId);
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(path.join(stateDir, "state", "openclaw.sqlite"));
  try {
    const row = database
      .prepare(
        "SELECT private_key_pem, mldsa_private_key_pem, mldsa_private_key_wrapped FROM device_identities WHERE identity_key = 'primary'",
      )
      .get() as {
      private_key_pem: string;
      mldsa_private_key_pem: string | null;
      mldsa_private_key_wrapped: Uint8Array | null;
    };
    expect(row.private_key_pem).toBe("");
    expect(row.mldsa_private_key_pem).toBeNull();
    expect(row.mldsa_private_key_wrapped).not.toBeNull();
  } finally {
    database.close();
  }
});

it("leaves legacy authorization on the retired id and gives the new id no token", async () => {
  const { env, provider, stateDir } = fixture();
  const legacy = legacyNodeIdentity();
  storeDeviceAuthToken({
    deviceId: legacy.deviceId,
    role: "operator",
    token: "legacy-token",
    scopes: ["operator.read"],
    env,
  });
  writeLegacy(stateDir, legacy.value);

  const result = await migrate(stateDir, env);
  const stored = readStoredDeviceIdentity({
    env,
    identityKey: "primary",
    wrappingKeyProvider: provider,
  });

  expect(result.warnings).toEqual([]);
  expect(loadDeviceAuthToken({ deviceId: legacy.deviceId, role: "operator", env })?.token).toBe(
    "legacy-token",
  );
  expect(loadDeviceAuthToken({ deviceId: stored!.deviceId, role: "operator", env })).toBeNull();
});

it("allocates a numbered archive when a different archive already exists", async () => {
  const { env, stateDir } = fixture();
  const prior = writeLegacy(stateDir, legacyNodeIdentity().value);
  const priorArchivePath = `${prior.path}.migrated`;
  fs.renameSync(prior.path, priorArchivePath);
  const current = writeLegacy(stateDir, legacyNodeIdentity().value);

  const result = await migrate(stateDir, env);

  expect(result.warnings).toEqual([]);
  expect(fs.readFileSync(priorArchivePath)).toEqual(prior.bytes);
  expect(fs.readFileSync(`${current.path}.migrated.2`)).toEqual(current.bytes);
  expect(fs.statSync(priorArchivePath).mode & 0o777).toBe(0o600);
  expect(fs.statSync(`${current.path}.migrated.2`).mode & 0o777).toBe(0o600);
});

it("skips a malformed occupied archive and allocates the next path", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  fs.writeFileSync(`${source.path}.migrated`, "not-json", { mode: 0o644 });

  const result = await migrate(stateDir, env);

  expect(result.warnings).toEqual([]);
  expect(fs.readFileSync(`${source.path}.migrated`, "utf8")).toBe("not-json");
  expect(fs.readFileSync(`${source.path}.migrated.2`)).toEqual(source.bytes);
});

it("removes an identical active duplicate when its archive already exists", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  fs.copyFileSync(source.path, `${source.path}.migrated`);

  const result = await migrate(stateDir, env);

  expect(result.warnings).toEqual([]);
  expect(result.changes.join("\n")).toContain("Removed duplicate retired Ed25519 source");
  expect(fs.existsSync(source.path)).toBe(false);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
  expect(fs.existsSync(`${source.path}.migrated.2`)).toBe(false);
});

it("resumes an interrupted claim and archives it", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const claimPath = `${source.path}.doctor-importing`;
  fs.renameSync(source.path, claimPath);

  const result = await migrate(stateDir, env);

  expect(result.warnings).toEqual([]);
  expect(fs.existsSync(claimPath)).toBe(false);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
});

it("does not overwrite a claim created after the destination check", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const claimPath = `${source.path}.doctor-importing`;
  const competitor = Buffer.from("competing claim");
  const inject = () => fs.writeFileSync(claimPath, competitor, { mode: 0o600 });
  archiveFault.beforeTargetCreate = { path: path.relative(stateDir, claimPath), run: inject };
  archiveFault.beforePublishTarget = { path: claimPath, run: inject };
  __setFsSafeTestHooksForTest({
    beforeRootFallbackMutation: (operation, targetPath) => {
      if (operation === "move" && targetPath === claimPath) {
        const pending = archiveFault.beforeTargetCreate;
        archiveFault.beforeTargetCreate = undefined;
        archiveFault.beforePublishTarget = undefined;
        pending?.run();
      }
    },
  });

  const result = await migrate(stateDir, env);

  expect(archiveFault.beforeTargetCreate).toBeUndefined();
  expect(archiveFault.beforePublishTarget).toBeUndefined();
  expect(result.warnings.join("\n")).toContain("Failed retiring legacy device identity");
  expect(fs.readFileSync(claimPath)).toEqual(competitor);
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(fs.existsSync(`${source.path}.migrated`)).toBe(false);
});

it("does not overwrite a source created after the restore destination check", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const claimPath = `${source.path}.doctor-importing`;
  const competitor = Buffer.from("competing source");
  const inject = () => fs.writeFileSync(source.path, competitor, { mode: 0o600 });
  archiveFault.beforeTargetCreate = { path: path.relative(stateDir, source.path), run: inject };
  archiveFault.beforePublishTarget = { path: source.path, run: inject };
  __setFsSafeTestHooksForTest({
    beforeRootFallbackMutation: (operation, targetPath) => {
      if (operation === "move" && targetPath === source.path) {
        const pending = archiveFault.beforeTargetCreate;
        archiveFault.beforeTargetCreate = undefined;
        archiveFault.beforePublishTarget = undefined;
        pending?.run();
      }
    },
  });

  const result = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterReceiptRecorded: () => {
      throw new Error("injected retirement interruption");
    },
  });

  expect(archiveFault.beforeTargetCreate).toBeUndefined();
  expect(archiveFault.beforePublishTarget).toBeUndefined();
  expect(result.warnings.join("\n")).toContain("injected retirement interruption");
  expect(fs.readFileSync(source.path)).toEqual(competitor);
  expect(fs.readFileSync(claimPath)).toEqual(source.bytes);
  expect(fs.existsSync(`${source.path}.migrated`)).toBe(false);
});

it("resumes a copy interrupted with identical source and claim names", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const claimPath = `${source.path}.doctor-importing`;
  fs.copyFileSync(source.path, claimPath);

  const result = await migrate(stateDir, env);

  expect(result.warnings).toEqual([]);
  expect(fs.existsSync(source.path)).toBe(false);
  expect(fs.existsSync(claimPath)).toBe(false);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
});

it("resumes an atomic publication interrupted while both names share one inode", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const claimPath = `${source.path}.doctor-importing`;
  fs.linkSync(source.path, claimPath);
  expect(fs.statSync(source.path).nlink).toBe(2);

  const result = await migrate(stateDir, env);

  expect(result.warnings).toEqual([]);
  expect(fs.existsSync(source.path)).toBe(false);
  expect(fs.existsSync(claimPath)).toBe(false);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
});

it("preserves both paths when a partial or conflicting claim exists", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const claimPath = `${source.path}.doctor-importing`;
  fs.writeFileSync(claimPath, source.bytes.subarray(0, 10), { mode: 0o600 });

  const result = await migrate(stateDir, env);

  expect(result.warnings.join("\n")).toContain("source path already exists");
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(fs.readFileSync(claimPath)).toEqual(source.bytes.subarray(0, 10));
  expect(fs.existsSync(`${source.path}.migrated`)).toBe(false);
});

it.each(["open", "chmod", "sync", "read", "remove"] as const)(
  "preserves the source after archive %s failure and safely retries",
  async (operation) => {
    const { env, stateDir } = fixture();
    const source = writeLegacy(stateDir, legacyNodeIdentity().value);
    archiveFault.operation = operation;
    const failed = await migrate(stateDir, env);
    expect(archiveFault.fired).toBe(true);
    expect(failed.warnings.join("\n")).toContain(`injected archive ${operation} failure`);
    expect(fs.readFileSync(source.path)).toEqual(source.bytes);
    expect(fs.existsSync(`${source.path}.doctor-importing`)).toBe(false);
    expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
    expect(
      openOpenClawStateDatabase({ env })
        .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
        .get("legacy-device-identity-json"),
    ).toEqual({ removed_source: 0 });
    const retried = await migrate(stateDir, env);
    expect(retried.warnings).toEqual([]);
    expect(retried.changes.join("\n")).toContain("Removed duplicate retired Ed25519 source");
  },
);

it.each(["corrupt", "symlink", "hardlink"] as const)(
  "preserves the source when the unverified archive becomes %s",
  async (kind) => {
    const { env, stateDir } = fixture();
    const source = writeLegacy(stateDir, legacyNodeIdentity().value);
    const archivePath = `${source.path}.migrated`;
    const unrelatedPath = path.join(stateDir, "unrelated");
    fs.writeFileSync(unrelatedPath, "unrelated bytes", { mode: 0o640 });
    archiveFault.beforeRead = () => {
      if (kind === "corrupt") {
        fs.writeFileSync(archivePath, "corrupt archive");
      } else {
        fs.unlinkSync(archivePath);
        if (kind === "symlink") {
          fs.symlinkSync(unrelatedPath, archivePath);
        } else {
          fs.linkSync(unrelatedPath, archivePath);
        }
      }
    };
    const failed = await migrate(stateDir, env);
    expect(failed.warnings.join("\n")).toContain("Failed retiring legacy device identity");
    expect(fs.readFileSync(source.path)).toEqual(source.bytes);
    expect(fs.existsSync(`${source.path}.doctor-importing`)).toBe(false);
    expect(fs.statSync(source.path).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(unrelatedPath, "utf8")).toBe("unrelated bytes");
    expect(fs.statSync(unrelatedPath).mode & 0o777).toBe(0o640);
    expect(
      openOpenClawStateDatabase({ env })
        .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
        .get("legacy-device-identity-json"),
    ).toEqual({ removed_source: 0 });
    if (kind === "corrupt") {
      expect((await migrate(stateDir, env)).warnings).toEqual([]);
      expect(fs.readFileSync(`${source.path}.migrated.2`)).toEqual(source.bytes);
    }
  },
);

it("retains a claim changed while its archive is being verified", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const changed = Buffer.from(`${JSON.stringify(legacyNodeIdentity().value)}\n`);
  archiveFault.beforeRead = () => {
    fs.writeFileSync(`${source.path}.doctor-importing`, changed);
  };
  const failed = await migrate(stateDir, env);
  expect(failed.warnings.join("\n")).toContain("claim changed during archival");
  expect(fs.readFileSync(source.path)).toEqual(changed);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
});

it("does not overwrite an archive occupied after planning", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  archiveFault.beforeCreate = () => {
    fs.writeFileSync(`${source.path}.migrated`, "competing archive", { mode: 0o600 });
  };
  const failed = await migrate(stateDir, env);
  expect(failed.warnings.join("\n")).toContain("Failed retiring legacy device identity");
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(fs.readFileSync(`${source.path}.migrated`, "utf8")).toBe("competing archive");
  expect((await migrate(stateDir, env)).warnings).toEqual([]);
  expect(fs.readFileSync(`${source.path}.migrated.2`)).toEqual(source.bytes);
});

it("keeps the original source when archive directory sync fails", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  archiveFault.directorySyncFailure = true;
  const failed = await migrate(stateDir, env);
  expect(failed.warnings.join("\n")).toContain("injected archive directory sync failure");
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
  expect(
    openOpenClawStateDatabase({ env })
      .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 0 });
  expect((await migrate(stateDir, env)).warnings).toEqual([]);
});

it("keeps the receipt pending and restores the source when interrupted before archival", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const detected = detectLegacyDeviceIdentity({
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
  });

  const interrupted = await migrateLegacyDeviceIdentity({
    detected,
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterReceiptRecorded: () => {
      throw new Error("simulated interruption");
    },
  });
  expect(interrupted.warnings.join("\n")).toContain("simulated interruption");
  expect(interrupted.changes).toContain("Generated a new ML-DSA primary device identity.");
  expect(interrupted.notices).toContain(
    "The retired Ed25519 device authorization was not transferred; approve the new ML-DSA device identity.",
  );
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(
    openOpenClawStateDatabase({ env })
      .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 0 });

  const retried = await migrate(stateDir, env);
  expect(retried.warnings).toEqual([]);
  expect(fs.existsSync(source.path)).toBe(false);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
  expect(
    openOpenClawStateDatabase({ env })
      .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 1 });
});

it("reconciles a verified archive after finalization is interrupted", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const interrupted = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterArchiveVerified: () => {
      throw new Error("simulated post-archive interruption");
    },
  });
  expect(interrupted.warnings.join("\n")).toContain("simulated post-archive interruption");
  expect(fs.existsSync(source.path)).toBe(false);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
  const db = openOpenClawStateDatabase({ env }).db;
  expect(
    db
      .prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 0 });

  const retried = await migrate(stateDir, env);
  expect(retried.warnings).toEqual([]);
  expect(retried.changes.join("\n")).toContain("Confirmed retired Ed25519 device identity archive");
  expect(
    db
      .prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 1 });
});

it("does not finalize a receipt if the archive changes after the move", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const result = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterArchiveVerified: () => {
      fs.writeFileSync(`${source.path}.migrated`, "tampered archive");
    },
  });
  expect(result.warnings.join("\n")).toContain("Failed retiring legacy device identity");
  expect(
    openOpenClawStateDatabase({ env })
      .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 0 });
  const retried = await migrate(stateDir, env);
  expect(retried.warnings.join("\n")).toContain("no matching archive exists");
});

it("does not finalize while the retired source reappears", async () => {
  const { env, stateDir } = fixture();
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const result = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterArchiveVerified: () => {
      fs.writeFileSync(source.path, source.bytes);
    },
  });
  expect(result.warnings.join("\n")).toContain("source or claim reappeared");
  expect(
    openOpenClawStateDatabase({ env })
      .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 0 });
  const retried = await migrate(stateDir, env);
  expect(retried.warnings).toEqual([]);
  expect(retried.changes.join("\n")).toContain("Removed duplicate retired Ed25519 source");
});

it("reconciles a numbered archive after an interrupted move", async () => {
  const { env, stateDir } = fixture();
  const prior = writeLegacy(stateDir, legacyNodeIdentity().value);
  fs.renameSync(prior.path, `${prior.path}.migrated`);
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const interrupted = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterArchiveVerified: () => {
      throw new Error("simulated numbered-archive interruption");
    },
  });
  expect(interrupted.warnings.join("\n")).toContain("numbered-archive interruption");
  expect(fs.readFileSync(`${source.path}.migrated.2`)).toEqual(source.bytes);
  fs.unlinkSync(`${source.path}.migrated`);
  const retried = await migrate(stateDir, env);
  expect(retried.warnings).toEqual([]);
  expect(retried.changes.join("\n")).toContain(`${source.path}.migrated.2`);
});

it("finalizes a pending archive despite a native Apple row requiring verification", async () => {
  const { env, stateDir } = fixture();
  const db = openOpenClawStateDatabase({ env }).db;
  const pub = Buffer.alloc(1952, 3);
  db.prepare(
    "INSERT INTO device_identities(identity_key,device_id,public_key_pem,private_key_pem,created_at_ms,updated_at_ms) VALUES(?,?,?,?,1,1)",
  ).run(
    "apple-mldsa65-primary",
    createHash("sha256").update(pub).digest("hex"),
    `MLDSA65-PUBLIC-KEY:${pub.toString("base64")}`,
    `MLDSA65-SEED:${Buffer.alloc(32, 4).toString("base64")}`,
  );
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const interrupted = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterArchiveVerified: () => {
      throw new Error("simulated Apple archive interruption");
    },
  });
  expect(interrupted.warnings.join("\n")).toContain("Apple archive interruption");
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
  const retried = await migrate(stateDir, env);
  expect(retried.warnings.join("\n")).toContain("requires native Apple verification");
  expect(retried.changes.join("\n")).toContain("Confirmed retired Ed25519 device identity archive");
  expect(
    db
      .prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 1 });
});

it("upgrades a recoverable identity row before finalizing a pending archive", async () => {
  const { env, provider, stateDir } = fixture();
  writeLegacy(stateDir, legacyNodeIdentity().value);
  const interrupted = await migrateLegacyDeviceIdentity({
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    afterArchiveVerified: () => {
      throw new Error("simulated upgrade interruption");
    },
  });
  expect(interrupted.warnings.join("\n")).toContain("upgrade interruption");
  const custom = generateStoredDeviceIdentity(5, undefined, { allowPlaintextPrivateKey: true });
  insertStoredDeviceIdentityIfAbsent(custom, { env, identityKey: "custom" });

  const retried = await migrate(stateDir, env);
  expect(retried.warnings).toEqual([]);
  expect(retried.changes).toContain(
    'Upgraded authenticated wrapping for device identity "custom" in SQLite.',
  );
  expect(
    readStoredDeviceIdentity({ env, identityKey: "custom", wrappingKeyProvider: provider }),
  ).toMatchObject({ deviceId: custom.deviceId, privateKeyPem: custom.privateKeyPem });
  expect(
    openOpenClawStateDatabase({ env })
      .db.prepare("SELECT removed_source FROM migration_sources WHERE migration_kind = ?")
      .get("legacy-device-identity-json"),
  ).toEqual({ removed_source: 1 });
});

it("restores the legacy source when the existing wrapping key cannot be opened", async () => {
  const { env, provider, stateDir } = fixture();
  const existing = insertStoredDeviceIdentityIfAbsent(
    generateStoredDeviceIdentity(1_700_000_000_002, provider),
    { env, identityKey: "primary", wrappingKeyProvider: provider },
  );
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const wrongKeyPath = path.join(stateDir, "wrong-wrap-key.b64");
  fs.writeFileSync(wrongKeyPath, Buffer.alloc(32, 99).toString("base64url"), { mode: 0o600 });
  const wrongEnv = {
    ...env,
    OPENCLAW_WRAP_KEY_FILE: wrongKeyPath,
    OPENCLAW_WRAP_KEY_ID: "wrong-key",
  };

  const result = await migrate(stateDir, wrongEnv);

  expect(result.warnings.join("\n")).toContain("Restore its wrapping key");
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(fs.existsSync(`${source.path}.migrated`)).toBe(false);
  expect(
    readStoredDeviceIdentity({ env, identityKey: "primary", wrappingKeyProvider: provider })
      ?.deviceId,
  ).toBe(existing.deviceId);
});

it("creates primary and upgrades custom rows atomically during interrupted-claim retirement", async () => {
  const { env, provider, stateDir } = fixture();
  const custom = generateStoredDeviceIdentity(3, undefined, { allowPlaintextPrivateKey: true });
  insertStoredDeviceIdentityIfAbsent(custom, { env, identityKey: "custom" });
  const db = openOpenClawStateDatabase({ env }).db;
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  fs.renameSync(source.path, `${source.path}.doctor-importing`);
  db.exec(
    "CREATE TRIGGER reject_primary BEFORE INSERT ON device_identities WHEN NEW.identity_key='primary' BEGIN SELECT RAISE(ABORT,'injected primary failure'); END",
  );
  const before = db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all();
  const failed = await migrate(stateDir, env);
  expect(failed.warnings.join("\n")).toContain("injected primary failure");
  expect(db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all()).toEqual(before);
  expect(db.prepare("SELECT * FROM migration_sources").all()).toEqual([]);
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  db.exec("DROP TRIGGER reject_primary");
  const retried = await migrate(stateDir, env);
  expect(retried.warnings).toEqual([]);
  expect(retried.changes).toContain(
    'Upgraded authenticated wrapping for device identity "custom" in SQLite.',
  );
  expect(
    readStoredDeviceIdentity({ env, wrappingKeyProvider: provider, identityKey: "custom" }),
  ).toMatchObject({ deviceId: custom.deviceId, privateKeyPem: custom.privateKeyPem });
  const primary = readStoredDeviceIdentity({ env, wrappingKeyProvider: provider });
  expect(primary).not.toBeNull();
  const census = db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all();
  expect((await migrate(stateDir, env)).changes).toEqual([]);
  expect(db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all()).toEqual(census);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
});

it("does not record a retirement receipt or archive after cleanup-time population corruption", async () => {
  const { env, provider, stateDir } = fixture();
  insertStoredDeviceIdentityIfAbsent(
    generateStoredDeviceIdentity(4, provider, { identityKey: "custom" }),
    { env, identityKey: "custom", wrappingKeyProvider: provider },
  );
  const db = openOpenClawStateDatabase({ env }).db;
  const source = writeLegacy(stateDir, legacyNodeIdentity().value);
  const result = await migrateLegacyDeviceIdentity({
    stateDir,
    env,
    doctorOnlyStateMigrations: true,
    detected: detectLegacyDeviceIdentity({ stateDir, env, doctorOnlyStateMigrations: true }),
    beforeCleanup: () => {
      db.prepare(
        "UPDATE device_identities SET device_id='broken' WHERE identity_key='custom'",
      ).run();
    },
  });
  expect(result.warnings.join("\n")).toContain("population");
  expect(db.prepare("SELECT * FROM migration_sources").all()).toEqual([]);
  expect(db.prepare("SELECT * FROM migration_runs").all()).toEqual([]);
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);
  expect(fs.existsSync(`${source.path}.migrated`)).toBe(false);
});

it("keeps Apple rows pending and visible during legacy retirement", async () => {
  const { env, stateDir } = fixture();
  const db = openOpenClawStateDatabase({ env }).db;
  const pub = Buffer.alloc(1952, 3);
  db.prepare(
    "INSERT INTO device_identities(identity_key,device_id,public_key_pem,private_key_pem,created_at_ms,updated_at_ms) VALUES(?,?,?,?,1,1)",
  ).run(
    "apple-mldsa65-primary",
    createHash("sha256").update(pub).digest("hex"),
    `MLDSA65-PUBLIC-KEY:${pub.toString("base64")}`,
    `MLDSA65-SEED:${Buffer.alloc(32, 4).toString("base64")}`,
  );
  const before = db
    .prepare("SELECT * FROM device_identities WHERE identity_key='apple-mldsa65-primary'")
    .get();
  writeLegacy(stateDir, legacyNodeIdentity().value);
  const result = await migrate(stateDir, env);
  expect(result.warnings).toEqual([
    'Device identity "apple-mldsa65-primary" was preserved and still requires native Apple verification.',
  ]);
  expect(
    db.prepare("SELECT * FROM device_identities WHERE identity_key='apple-mldsa65-primary'").get(),
  ).toEqual(before);
});

it.each([
  "source/custom",
  "claim/custom",
  "source/primary",
  "claim/primary",
  "source/missing-key",
  "claim/missing-key",
])(
  "blocks legacy retirement without changing the population or recording success (%s)",
  async (scenario) => {
    const { env, stateDir } = fixture();
    insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(1, undefined, { allowPlaintextPrivateKey: true }),
      { env, identityKey: "a-valid" },
    );
    const badKey = scenario.endsWith("primary") ? "primary" : "z-bad";
    if (scenario.endsWith("missing-key")) {
      const unavailable = new FileKeyring(env.OPENCLAW_WRAP_KEY_FILE, "historical-unavailable");
      providers.push(unavailable);
      insertStoredDeviceIdentityIfAbsent(
        generateStoredDeviceIdentity(2, unavailable, { identityKey: badKey }),
        { env, identityKey: badKey, wrappingKeyProvider: unavailable },
      );
    } else {
      insertStoredDeviceIdentityIfAbsent(
        generateStoredDeviceIdentity(2, undefined, { allowPlaintextPrivateKey: true }),
        { env, identityKey: badKey },
      );
    }
    const db = openOpenClawStateDatabase({ env }).db;
    if (!scenario.endsWith("missing-key")) {
      db.prepare("UPDATE device_identities SET device_id='broken' WHERE identity_key=?").run(
        badKey,
      );
    }
    const before = db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all();
    const source = writeLegacy(stateDir, legacyNodeIdentity().value);
    if (scenario.startsWith("claim")) {
      fs.renameSync(source.path, `${source.path}.doctor-importing`);
    }
    const result = await migrate(stateDir, env);
    expect(result.changes).toEqual([]);
    expect(result.warnings.join("\n")).toContain("population");
    expect(db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all()).toEqual(
      before,
    );
    expect(db.prepare("SELECT * FROM migration_sources").all()).toEqual([]);
    expect(db.prepare("SELECT * FROM migration_runs").all()).toEqual([]);
    expect(fs.readFileSync(source.path)).toEqual(source.bytes);
    expect(fs.existsSync(`${source.path}.migrated`)).toBe(false);
  },
);
