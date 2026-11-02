import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
  repairInvalidStoredDeviceIdentity,
  upgradeDeviceIdentityPopulationWrapped,
} from "../infra/device-identity-store.js";
import { activateDeviceIdentityWriteGeneration } from "../infra/device-identity.js";
import { requireNodeSqlite } from "../infra/node-sqlite.js";
import { runSqliteImmediateTransactionSync } from "../infra/sqlite-transaction.js";
import { EnvKeyring } from "../security/keyring-provider.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";
import { activateIdentityWriteSchemaInTransaction } from "./openclaw-state-db-identity-activation.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
  OPENCLAW_STATE_SCHEMA_VERSION,
  repairOpenClawStateDatabaseSchema,
} from "./openclaw-state-db.js";
import { identityWriteV7ObjectsSql } from "./openclaw-state-schema-versioned.js";

// v7 storage is present; the write fence remains dormant until explicit activation.
const candidateFenceSql = `
  UPDATE device_identities SET write_generation = 1, write_revision = 0;
  INSERT INTO identity_write_generation VALUES (1, 1, 'key-B');
  INSERT INTO identity_write_receipts VALUES ('activation', 1, 'key-B');

`;

const roots: string[] = [];
const secondaryConnections: DatabaseSync[] = [];
const fixtureKeys: Buffer[] = [];
const fixtureProviders: EnvKeyring[] = [];

function activationProvider(key: Buffer): EnvKeyring {
  const provider = new EnvKeyring(
    "ACTIVATION_TEST_KEY",
    { ACTIVATION_TEST_KEY: key.toString("base64url") },
    "key-B",
  );
  fixtureProviders.push(provider);
  return provider;
}

function fixture(options: { v7?: boolean } = {}): {
  old: DatabaseSync;
  admin: DatabaseSync;
  databasePath: string;
} {
  const stateDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "identity-v7-fence-")));
  roots.push(stateDir);
  const opened = openOpenClawStateDatabase({ env: { OPENCLAW_STATE_DIR: stateDir } });
  const { DatabaseSync } = requireNodeSqlite();
  const admin = new DatabaseSync(opened.path);
  secondaryConnections.push(admin);
  if (options.v7 !== false) {
    upgradeFixtureToV7(admin);
  }
  return { old: opened.db, admin, databasePath: opened.path };
}

function upgradeFixtureToV7(admin: DatabaseSync): void {
  admin.exec("BEGIN IMMEDIATE");
  try {
    admin.exec(`
      ALTER TABLE device_identities ADD COLUMN write_generation INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE device_identities ADD COLUMN write_revision INTEGER NOT NULL DEFAULT 0;
    `);
    admin.exec(identityWriteV7ObjectsSql());
    admin.exec(
      "UPDATE schema_meta SET schema_version = 7 WHERE meta_key = 'primary'; PRAGMA user_version = 7;",
    );
    admin.exec("COMMIT");
  } catch (error) {
    admin.exec("ROLLBACK");
    throw error;
  }
}

function activateCandidate(admin: DatabaseSync, failBeforeCommit = false): void {
  admin.exec("BEGIN IMMEDIATE");
  try {
    admin.exec(candidateFenceSql);
    if (failBeforeCommit) {
      throw new Error("injected-before-commit");
    }
    admin.exec("COMMIT");
  } catch (error) {
    admin.exec("ROLLBACK");
    throw error;
  }
}

function insertSixColumnIdentity(db: DatabaseSync, identityKey: string): void {
  db.prepare(
    `INSERT INTO device_identities (
      identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms
    ) VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(identityKey, `device-${identityKey}`, "public", "MLDSA65-SEED:fixture", 1, 1);
}

function insertV7Identity(
  db: DatabaseSync,
  identityKey: string,
  generation: number,
  keyId: string | null,
): void {
  db.prepare(
    `INSERT INTO device_identities (
      identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms,
      mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id,
      write_generation, write_revision
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    identityKey,
    `device-${identityKey}`,
    "public",
    keyId ? "" : "MLDSA65-SEED:fixture",
    1,
    1,
    keyId ? "public" : null,
    keyId ? Buffer.from("fixture-envelope") : null,
    keyId,
    generation,
    0,
  );
}

afterEach(() => {
  for (const provider of fixtureProviders.splice(0)) {
    provider.release();
  }
  for (const connection of secondaryConnections.splice(0)) {
    connection.close();
  }
  closeOpenClawStateDatabaseForTest();
  for (const key of fixtureKeys.splice(0)) {
    key.fill(0);
  }
  for (const root of roots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("dormant v7 identity write fence candidate", () => {
  it("blocks activation behind another process's write and rejects that stale writer after release", async () => {
    const { admin, databasePath } = fixture({ v7: false });
    const key = Buffer.alloc(32, 9);
    fixtureKeys.push(key);
    const provider = activationProvider(key);
    const baseline = generateStoredDeviceIdentity(1_700_000_000_000, provider, {
      identityKey: "baseline",
    });
    insertStoredDeviceIdentityIfAbsent(baseline, {
      path: databasePath,
      identityKey: "baseline",
      wrappingKeyProvider: provider,
    });
    closeOpenClawStateDatabaseForTest();

    const worker = String.raw`
      import { DatabaseSync } from "node:sqlite";
      import readline from "node:readline";
      const db = new DatabaseSync(process.argv[1]);
      const insert = db.prepare("INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES ('stale', 'stale-device', 'public', 'MLDSA65-SEED:fixture', 1, 1)");
      db.exec("BEGIN IMMEDIATE");
      process.stdout.write("held\n");
      for await (const command of readline.createInterface({ input: process.stdin })) {
        if (command === "release") {
          db.exec("ROLLBACK");
          process.stdout.write("released\n");
        } else if (command === "write") {
          try {
            insert.run();
            process.stdout.write("written\n");
          } catch (error) {
            process.stdout.write(JSON.stringify({ error: String(error) }) + "\n");
          }
        }
      }
      db.close();
    `;
    const child = spawn(process.execPath, ["--input-type=module", "-e", worker, databasePath], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const lines = readline.createInterface({ input: child.stdout });
    const iterator = lines[Symbol.asyncIterator]();
    const nextLine = async (): Promise<string> => {
      const timeout = AbortSignal.timeout(15_000);
      const result = await new Promise<IteratorResult<string>>((resolve, reject) => {
        const onAbort = () => reject(new Error("stale writer did not respond"));
        timeout.addEventListener("abort", onAbort, { once: true });
        iterator.next().then(
          (value) => {
            timeout.removeEventListener("abort", onAbort);
            resolve(value);
          },
          (error: unknown) => {
            timeout.removeEventListener("abort", onAbort);
            reject(error instanceof Error ? error : new Error(String(error)));
          },
        );
      });
      if (result.done) {
        throw new Error("stale writer exited before replying");
      }
      return result.value;
    };
    try {
      expect(await nextLine()).toBe("held");
      expect(() =>
        activateDeviceIdentityWriteGeneration("held-writer", {
          path: databasePath,
          wrappingKeyProvider: provider,
        }),
      ).toThrow();
      expect(admin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
      expect(admin.prepare("SELECT COUNT(*) AS n FROM device_identities").get()).toEqual({ n: 1 });
      child.stdin.write("release\n");
      expect(await nextLine()).toBe("released");
      expect(
        activateDeviceIdentityWriteGeneration("held-writer", {
          path: databasePath,
          wrappingKeyProvider: provider,
        }),
      ).toEqual({ generation: 1, replayed: false, databaseState: "current" });
      child.stdin.write("write\n");
      expect(JSON.parse(await nextLine())).toEqual({
        error: expect.stringContaining("identity-write-fence"),
      });
      expect(admin.prepare("SELECT COUNT(*) AS n FROM device_identities").get()).toEqual({ n: 1 });
    } finally {
      child.kill();
      lines.close();
    }
  }, 60_000);

  it("activates a verified v6 population once and replays only its receipt", () => {
    const { admin, databasePath } = fixture({ v7: false });
    const key = Buffer.alloc(32, 9);
    fixtureKeys.push(key);
    const provider = activationProvider(key);
    const baseline = generateStoredDeviceIdentity(1_700_000_000_000, provider, {
      identityKey: "baseline",
    });
    insertStoredDeviceIdentityIfAbsent(baseline, {
      path: databasePath,
      identityKey: "baseline",
      wrappingKeyProvider: provider,
    });
    expect(() =>
      activateDeviceIdentityWriteGeneration("activation-1", {
        path: databasePath,
        wrappingKeyProvider: provider,
      }),
    ).toThrow(/shared handle is open/);
    closeOpenClawStateDatabaseForTest();

    expect(
      activateDeviceIdentityWriteGeneration("activation-1", {
        path: databasePath,
        wrappingKeyProvider: provider,
      }),
    ).toEqual({ generation: 1, replayed: false, databaseState: "current" });
    expect(admin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 7 });
    expect(
      admin.prepare("SELECT schema_version FROM schema_meta WHERE meta_key = 'primary'").get(),
    ).toEqual({ schema_version: 7 });
    expect(
      admin.prepare("SELECT generation, new_write_key_id FROM identity_write_generation").get(),
    ).toEqual({
      generation: 1,
      new_write_key_id: "key-B",
    });
    expect(admin.prepare("SELECT * FROM identity_write_receipts").get()).toEqual({
      receipt_id: "activation-1",
      generation: 1,
      new_write_key_id: "key-B",
    });
    expect(
      admin.prepare("SELECT write_generation, write_revision FROM device_identities").get(),
    ).toEqual({ write_generation: 1, write_revision: 0 });
    expect(() => insertSixColumnIdentity(admin, "stale-writer")).toThrow(/identity-write-fence/);
    expect(
      activateDeviceIdentityWriteGeneration("activation-1", {
        path: databasePath,
        wrappingKeyProvider: provider,
      }),
    ).toEqual({ generation: 1, replayed: true, databaseState: "current" });
    expect(activateDeviceIdentityWriteGeneration("activation-1", { path: databasePath })).toEqual({
      generation: 1,
      replayed: true,
      databaseState: "current",
    });
    expect(() =>
      activateDeviceIdentityWriteGeneration("activation-other", {
        path: databasePath,
        wrappingKeyProvider: provider,
      }),
    ).toThrow(/different receipt or key/);
  });

  it("refuses an opaque wrapping provider before modifying v6", () => {
    const { admin, databasePath } = fixture({ v7: false });
    closeOpenClawStateDatabaseForTest();
    const key = Buffer.alloc(32, 5);
    fixtureKeys.push(key);
    const opaque: WrappingKeyProvider = {
      getActiveKey: () => ({ key, keyId: "key-B" }),
      getKeyById: () => key,
    };
    expect(() =>
      activateDeviceIdentityWriteGeneration("opaque-provider", {
        path: databasePath,
        wrappingKeyProvider: opaque,
      }),
    ).toThrow(/opaque-provider/);
    expect(admin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
  });

  it("refuses Apple seed rows without native verification before changing v6", () => {
    const { admin, databasePath } = fixture({ v7: false });
    const publicRaw = Buffer.alloc(1952, 3);
    const publicKey = `MLDSA65-PUBLIC-KEY:${publicRaw.toString("base64")}`;
    const seed = `MLDSA65-SEED:${Buffer.alloc(32, 4).toString("base64")}`;
    admin
      .prepare(
        `INSERT INTO device_identities
         (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms)
         VALUES (?, ?, ?, ?, 1, 1)`,
      )
      .run(
        "apple-mldsa65-primary",
        createHash("sha256").update(publicRaw).digest("hex"),
        publicKey,
        seed,
      );
    closeOpenClawStateDatabaseForTest();
    const key = Buffer.alloc(32, 5);
    fixtureKeys.push(key);
    const provider = activationProvider(key);
    expect(() =>
      activateDeviceIdentityWriteGeneration("apple-pending", {
        path: databasePath,
        wrappingKeyProvider: provider,
      }),
    ).toThrow(/native verification/);
    expect(admin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
    expect(
      admin
        .prepare(
          "SELECT name FROM pragma_table_info('device_identities') WHERE name = 'write_generation'",
        )
        .get(),
    ).toBeUndefined();
  });

  it("rolls schema, owner, receipt and row metadata back together on interrupted activation", () => {
    const { admin, databasePath } = fixture({ v7: false });
    insertSixColumnIdentity(admin, "legacy");
    expect(() =>
      runSqliteImmediateTransactionSync(admin, () => {
        activateIdentityWriteSchemaInTransaction(admin, databasePath, "interrupted", "key-B");
        throw new Error("injected-before-commit");
      }),
    ).toThrow("injected-before-commit");
    expect(admin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
    expect(
      admin.prepare("SELECT schema_version FROM schema_meta WHERE meta_key = 'primary'").get(),
    ).toEqual({ schema_version: 6 });
    expect(
      admin
        .prepare(
          "SELECT name FROM pragma_table_info('device_identities') WHERE name = 'write_generation'",
        )
        .get(),
    ).toBeUndefined();
    expect(
      admin.prepare("SELECT name FROM sqlite_schema WHERE name = 'identity_write_receipts'").get(),
    ).toBeUndefined();
    expect(admin.prepare("SELECT identity_key FROM device_identities").get()).toEqual({
      identity_key: "legacy",
    });
  });

  it("upgrades a v6-shaped database without losing an existing identity", () => {
    const { old, admin, databasePath } = fixture({ v7: false });
    insertSixColumnIdentity(old, "apple-mldsa65-primary");
    expect(old.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
    closeOpenClawStateDatabaseForTest();
    const stillV6 = openOpenClawStateDatabase({ path: databasePath }).db;
    expect(stillV6.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
    expect(
      stillV6
        .prepare(
          "SELECT name FROM pragma_table_info('device_identities') WHERE name = 'write_generation'",
        )
        .get(),
    ).toBeUndefined();
    closeOpenClawStateDatabaseForTest();
    upgradeFixtureToV7(admin);

    const upgraded = openOpenClawStateDatabase({ path: databasePath }).db;
    expect(upgraded.prepare("PRAGMA user_version").get()).toEqual({ user_version: 7 });
    expect(
      upgraded
        .prepare(
          "SELECT identity_key, write_generation, write_revision FROM device_identities WHERE identity_key = 'apple-mldsa65-primary'",
        )
        .get(),
    ).toEqual({ identity_key: "apple-mldsa65-primary", write_generation: 0, write_revision: 0 });
    expect(
      upgraded
        .prepare(
          "SELECT name FROM sqlite_schema WHERE type = 'trigger' AND name = 'identity_write_insert'",
        )
        .get(),
    ).toEqual({ name: "identity_write_insert" });
    closeOpenClawStateDatabaseForTest();
    repairOpenClawStateDatabaseSchema({ path: databasePath });
    const repaired = openOpenClawStateDatabase({ path: databasePath }).db;
    expect(repaired.prepare("PRAGMA user_version").get()).toEqual({ user_version: 7 });
  });

  it("keeps the v7 write fence dormant until activation", () => {
    const { old } = fixture();
    expect(OPENCLAW_STATE_SCHEMA_VERSION).toBe(7);
    expect(old.prepare("PRAGMA user_version").get()).toEqual({ user_version: 7 });
    expect(
      old
        .prepare(
          "SELECT name FROM pragma_table_info('device_identities') WHERE name = 'write_generation'",
        )
        .get(),
    ).toEqual({ name: "write_generation" });
    insertSixColumnIdentity(old, "apple-mldsa65-primary");
    expect(old.prepare("SELECT count(*) AS n FROM device_identities").get()).toEqual({ n: 1 });
  });

  it("keeps the current Node store writable on an already-open handle", () => {
    const { admin, databasePath } = fixture();
    const key = Buffer.alloc(32, 7);
    const provider: WrappingKeyProvider = {
      getActiveKey: () => ({ key, keyId: "key-B" }),
      getKeyById: (keyId) => (keyId === "key-B" ? key : null),
    };
    try {
      const baseline = generateStoredDeviceIdentity(1_700_000_000_000, provider, {
        identityKey: "baseline",
      });
      insertStoredDeviceIdentityIfAbsent(baseline, {
        path: databasePath,
        identityKey: "baseline",
        wrappingKeyProvider: provider,
      });
      expect(admin.prepare("SELECT count(*) AS n FROM device_identities").get()).toEqual({ n: 1 });

      activateCandidate(admin);
      const currentWriter = generateStoredDeviceIdentity(1_700_000_000_001, provider, {
        identityKey: "current-writer",
      });
      const inserted = insertStoredDeviceIdentityIfAbsent(currentWriter, {
        path: databasePath,
        identityKey: "current-writer",
        wrappingKeyProvider: provider,
      });
      expect(inserted.deviceId).toBe(currentWriter.deviceId);
      expect(
        readStoredDeviceIdentity({
          path: databasePath,
          identityKey: "current-writer",
          wrappingKeyProvider: provider,
        })?.deviceId,
      ).toBe(currentWriter.deviceId);
      expect(
        admin
          .prepare(
            "SELECT write_generation, write_revision FROM device_identities WHERE identity_key = 'current-writer'",
          )
          .get(),
      ).toEqual({ write_generation: 1, write_revision: 0 });
      expect(admin.prepare("SELECT count(*) AS n FROM device_identities").get()).toEqual({ n: 2 });
      const oldKey = Buffer.alloc(32, 8);
      fixtureKeys.push(oldKey);
      const oldProvider: WrappingKeyProvider = {
        getActiveKey: () => ({ key: oldKey, keyId: "key-A" }),
        getKeyById: (id) => (id === "key-A" ? oldKey : null),
      };
      const staleWriter = generateStoredDeviceIdentity(1_700_000_000_002, oldProvider, {
        identityKey: "stale-writer",
      });
      expect(() =>
        insertStoredDeviceIdentityIfAbsent(staleWriter, {
          path: databasePath,
          identityKey: "stale-writer",
          wrappingKeyProvider: oldProvider,
        }),
      ).toThrow(/identity-write-fence/);
      expect(admin.prepare("SELECT count(*) AS n FROM device_identities").get()).toEqual({ n: 2 });
    } finally {
      key.fill(0);
    }
  });

  it("upgrades a plaintext Node row while retaining a readable historical wrapped key", () => {
    const { admin, databasePath } = fixture();
    const keyA = Buffer.alloc(32, 3);
    const keyB = Buffer.alloc(32, 4);
    fixtureKeys.push(keyA, keyB);
    const historical: WrappingKeyProvider = {
      getActiveKey: () => ({ key: keyA, keyId: "key-A" }),
      getKeyById: (id) => (id === "key-A" ? keyA : null),
    };
    const current: WrappingKeyProvider = {
      getActiveKey: () => ({ key: keyB, keyId: "key-B" }),
      getKeyById: (id) => (id === "key-A" ? keyA : id === "key-B" ? keyB : null),
    };
    const oldIdentity = generateStoredDeviceIdentity(1_700_000_000_000, historical, {
      identityKey: "historical",
    });
    insertStoredDeviceIdentityIfAbsent(oldIdentity, {
      path: databasePath,
      identityKey: "historical",
      wrappingKeyProvider: historical,
    });
    const plaintext = generateStoredDeviceIdentity(1_700_000_000_001, undefined, {
      allowPlaintextPrivateKey: true,
    });
    insertStoredDeviceIdentityIfAbsent(plaintext, { path: databasePath });

    activateCandidate(admin);
    expect(
      upgradeDeviceIdentityPopulationWrapped({ path: databasePath, wrappingKeyProvider: current })
        .upgraded,
    ).toEqual(["primary"]);
    expect(
      admin
        .prepare(
          "SELECT write_generation, write_revision, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'primary'",
        )
        .get(),
    ).toEqual({
      write_generation: 1,
      write_revision: 1,
      mldsa_private_key_wrap_key_id: "key-B",
    });
    expect(
      admin
        .prepare(
          "SELECT mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'historical'",
        )
        .get(),
    ).toEqual({ mldsa_private_key_wrap_key_id: "key-A" });
    expect(
      readStoredDeviceIdentity({
        path: databasePath,
        identityKey: "historical",
        wrappingKeyProvider: current,
      })?.deviceId,
    ).toBe(oldIdentity.deviceId);
  });

  it("repairs an invalid row by revisioned update after activation", () => {
    const { admin, databasePath } = fixture();
    insertSixColumnIdentity(admin, "broken");
    activateCandidate(admin);
    const key = Buffer.alloc(32, 6);
    fixtureKeys.push(key);
    const provider: WrappingKeyProvider = {
      getActiveKey: () => ({ key, keyId: "key-B" }),
      getKeyById: (id) => (id === "key-B" ? key : null),
    };
    const candidate = generateStoredDeviceIdentity(1_700_000_000_002, provider, {
      identityKey: "broken",
    });
    const repaired = repairInvalidStoredDeviceIdentity(candidate, {
      path: databasePath,
      identityKey: "broken",
      wrappingKeyProvider: provider,
    });
    expect(repaired).toMatchObject({ repaired: true, rotated: true });
    expect(repaired.identity.deviceId).toBe(candidate.deviceId);
    expect(
      admin
        .prepare(
          "SELECT write_generation, write_revision, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'broken'",
        )
        .get(),
    ).toEqual({
      write_generation: 1,
      write_revision: 1,
      mldsa_private_key_wrap_key_id: "key-B",
    });
  });

  it("rejects old cached Node and Apple SQL but accepts explicit-generation SQL shapes", () => {
    const { old, admin, databasePath } = fixture();
    const keyA = Buffer.alloc(32, 9);
    fixtureKeys.push(keyA);
    const historicalProvider: WrappingKeyProvider = {
      getActiveKey: () => ({ key: keyA, keyId: "key-A" }),
      getKeyById: (keyId) => (keyId === "key-A" ? keyA : null),
    };
    const historicalIdentity = generateStoredDeviceIdentity(1_700_000_000_000, historicalProvider, {
      identityKey: "primary",
    });
    insertStoredDeviceIdentityIfAbsent(historicalIdentity, {
      path: databasePath,
      identityKey: "primary",
      wrappingKeyProvider: historicalProvider,
    });
    insertSixColumnIdentity(old, "apple-mldsa65-primary");
    insertSixColumnIdentity(old, "unwrapped-node");
    const oldNodeInsert = old.prepare(
      `INSERT INTO device_identities (
        identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms,
        mldsa_private_key_wrap_key_id
      ) VALUES ('old-node', 'd', 'p', '', 1, 1, 'key-B')
      ON CONFLICT (identity_key) DO NOTHING`,
    );
    const oldNodeUpdate = old.prepare(
      "UPDATE device_identities SET updated_at_ms = updated_at_ms WHERE identity_key = 'primary'",
    );
    const oldNodeDelete = old.prepare(
      "DELETE FROM device_identities WHERE identity_key = 'primary'",
    );
    const oldAppleInsert = old.prepare(
      `INSERT INTO device_identities (
        identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms
      ) VALUES ('apple-mldsa65-node', 'd', 'p', 'MLDSA65-SEED:fixture', 1, 1)`,
    );

    activateCandidate(admin);
    expect(admin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 7 });
    expect(
      admin.prepare("SELECT schema_version FROM schema_meta WHERE meta_key = 'primary'").get(),
    ).toEqual({
      schema_version: 7,
    });
    expect(oldNodeInsert.run.bind(oldNodeInsert)).toThrow(/identity-write-fence/);
    expect(oldNodeUpdate.run.bind(oldNodeUpdate)).toThrow(/identity-write-fence/);
    expect(oldNodeDelete.run.bind(oldNodeDelete)).toThrow(/identity-write-fence/);
    expect(oldAppleInsert.run.bind(oldAppleInsert)).toThrow(/identity-write-fence/);
    expect(() =>
      old
        .prepare(
          "UPDATE device_identities SET updated_at_ms = 2 WHERE identity_key = 'apple-mldsa65-primary'",
        )
        .run(),
    ).toThrow(/identity-write-fence/);
    expect(() => insertV7Identity(admin, "wrong-key", 1, "key-A")).toThrow(/identity-write-fence/);
    expect(() =>
      admin
        .prepare(
          "UPDATE device_identities SET mldsa_private_key_wrap_key_id = 'key-A', write_generation = 1, write_revision = 1 WHERE identity_key = 'unwrapped-node'",
        )
        .run(),
    ).toThrow(/identity-write-fence/);
    expect(() =>
      admin
        .prepare(
          "UPDATE device_identities SET mldsa_private_key_wrapped = ?, write_generation = 1, write_revision = 1 WHERE identity_key = 'primary'",
        )
        .run(Buffer.from("new-under-old-key")),
    ).toThrow(/identity-write-fence/);
    expect(() =>
      admin
        .prepare(
          "UPDATE device_identities SET mldsa_private_key_wrap_key_id = 'key-B', write_generation = 1, write_revision = 1 WHERE identity_key = 'primary'",
        )
        .run(),
    ).toThrow(/identity-write-fence/);

    insertV7Identity(admin, "new-node", 1, "key-B");
    insertV7Identity(admin, "apple-mldsa65-node", 1, null);
    admin
      .prepare(
        "UPDATE device_identities SET updated_at_ms = 2, write_generation = 1, write_revision = 1 WHERE identity_key = 'primary'",
      )
      .run();
    expect(
      admin
        .prepare(
          "SELECT mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'primary'",
        )
        .get(),
    ).toEqual({ mldsa_private_key_wrap_key_id: "key-A" });
    expect(
      readStoredDeviceIdentity({
        path: databasePath,
        identityKey: "primary",
        wrappingKeyProvider: historicalProvider,
      })?.deviceId,
    ).toBe(historicalIdentity.deviceId);
    expect(() =>
      admin
        .prepare(
          `INSERT OR REPLACE INTO device_identities (
          identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms,
          mldsa_private_key_wrap_key_id, write_generation, write_revision
        ) VALUES ('primary', 'd', 'p', '', 1, 1, 'key-B', 1, 0)`,
        )
        .run(),
    ).toThrow(/identity-write-fence/);
    expect(admin.prepare("SELECT count(*) AS n FROM device_identities").get()).toEqual({ n: 5 });

    closeOpenClawStateDatabaseForTest();
    expect(openOpenClawStateDatabase({ path: databasePath }).path).toBe(databasePath);
  });

  it("advances generations without ABA and rolls back an incomplete activation", () => {
    const { admin } = fixture();
    activateCandidate(admin);
    admin
      .prepare("UPDATE identity_write_generation SET generation = 2, new_write_key_id = 'key-C'")
      .run();
    expect(() => insertV7Identity(admin, "stale", 1, "key-B")).toThrow(/identity-write-fence/);
    admin
      .prepare("UPDATE identity_write_generation SET generation = 3, new_write_key_id = 'key-B'")
      .run();
    expect(() =>
      admin
        .prepare("INSERT OR REPLACE INTO identity_write_generation VALUES (1, 1, 'key-B')")
        .run(),
    ).toThrow(/identity-write-fence/);
    expect(() => insertV7Identity(admin, "aba", 1, "key-B")).toThrow(/identity-write-fence/);
    insertV7Identity(admin, "current", 3, "key-B");
    expect(() =>
      admin.prepare("UPDATE identity_write_generation SET generation = 1").run(),
    ).toThrow(/identity-write-fence/);

    const { old: rollbackOld, admin: rollbackAdmin } = fixture();
    insertSixColumnIdentity(rollbackOld, "primary");
    const beforeRow = rollbackAdmin
      .prepare("SELECT * FROM device_identities WHERE identity_key = 'primary'")
      .get();
    expect(() => activateCandidate(rollbackAdmin, true)).toThrow("injected-before-commit");
    expect(rollbackAdmin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 7 });
    expect(
      rollbackAdmin
        .prepare("SELECT schema_version FROM schema_meta WHERE meta_key = 'primary'")
        .get(),
    ).toEqual({
      schema_version: 7,
    });
    expect(
      rollbackAdmin
        .prepare(
          "SELECT name FROM pragma_table_info('device_identities') WHERE name = 'write_generation'",
        )
        .get(),
    ).toEqual({ name: "write_generation" });
    expect(
      rollbackAdmin
        .prepare("SELECT name FROM sqlite_schema WHERE name = 'identity_write_generation'")
        .get(),
    ).toEqual({ name: "identity_write_generation" });
    expect(rollbackAdmin.prepare("SELECT receipt_id FROM identity_write_receipts").all()).toEqual(
      [],
    );
    expect(
      rollbackAdmin.prepare("SELECT * FROM device_identities WHERE identity_key = 'primary'").get(),
    ).toEqual(beforeRow);
    insertSixColumnIdentity(rollbackOld, "apple-mldsa65-primary");
  });
});
