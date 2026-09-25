// Active regression coverage for retiring legacy Ed25519 identities into ML-DSA-only state.
import crypto, { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { FileKeyring, resetDefaultKeyringCache } from "../security/keyring-provider.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
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

it("restores and safely retries when interrupted after the receipt is marked", async () => {
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
    afterReceiptMarked: () => {
      throw new Error("simulated interruption");
    },
  });
  expect(interrupted.warnings.join("\n")).toContain("simulated interruption");
  expect(fs.readFileSync(source.path)).toEqual(source.bytes);

  const retried = await migrate(stateDir, env);
  expect(retried.warnings).toEqual([]);
  expect(fs.existsSync(source.path)).toBe(false);
  expect(fs.readFileSync(`${source.path}.migrated`)).toEqual(source.bytes);
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
