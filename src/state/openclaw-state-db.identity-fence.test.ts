import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
} from "../infra/device-identity-store.js";
import { requireNodeSqlite } from "../infra/node-sqlite.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
  OPENCLAW_STATE_SCHEMA_VERSION,
} from "./openclaw-state-db.js";

// A dormant v7 candidate. Keep the production schema and ordinary open path at v6.
const candidateFenceSql = `
  ALTER TABLE device_identities ADD COLUMN write_generation INTEGER NOT NULL DEFAULT 0;
  ALTER TABLE device_identities ADD COLUMN write_revision INTEGER NOT NULL DEFAULT 0;
  CREATE TABLE identity_write_generation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL CHECK (generation > 0),
    new_write_key_id TEXT NOT NULL CHECK (length(new_write_key_id) > 0)
  ) STRICT;
  INSERT INTO identity_write_generation VALUES (1, 1, 'key-B');
  CREATE TABLE identity_write_receipts (
    receipt_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL
  ) STRICT;
  UPDATE device_identities SET write_generation = 1, write_revision = 0;
  CREATE TRIGGER identity_write_insert BEFORE INSERT ON device_identities BEGIN
    SELECT CASE WHEN NEW.write_generation IS NOT (
      SELECT generation FROM identity_write_generation WHERE singleton = 1
    ) OR NEW.write_revision != 0 THEN RAISE(ABORT, 'identity-write-fence') END;
    SELECT CASE WHEN EXISTS (
      SELECT 1 FROM device_identities WHERE identity_key = NEW.identity_key
    ) THEN RAISE(ABORT, 'identity-write-fence') END;
    SELECT CASE WHEN NEW.identity_key NOT IN (
      'apple-mldsa65-primary', 'apple-mldsa65-node', 'apple-mldsa65-shareExtension'
    ) AND (
      NEW.mldsa_private_key_wrapped IS NULL OR
      length(NEW.mldsa_private_key_wrapped) = 0 OR
      NEW.mldsa_private_key_wrap_key_id IS NULL OR
      NEW.mldsa_private_key_wrap_key_id IS NOT (
        SELECT new_write_key_id FROM identity_write_generation WHERE singleton = 1
      )
    ) THEN RAISE(ABORT, 'identity-write-fence') END;
  END;
  CREATE TRIGGER identity_write_update BEFORE UPDATE ON device_identities BEGIN
    SELECT CASE WHEN NEW.identity_key != OLD.identity_key OR
      NEW.write_generation IS NOT (
        SELECT generation FROM identity_write_generation WHERE singleton = 1
      ) OR NEW.write_revision != OLD.write_revision + 1
    THEN RAISE(ABORT, 'identity-write-fence') END;
    SELECT CASE WHEN NEW.identity_key NOT IN (
      'apple-mldsa65-primary', 'apple-mldsa65-node', 'apple-mldsa65-shareExtension'
    ) AND (
      NEW.mldsa_private_key_wrapped IS NULL OR
      length(NEW.mldsa_private_key_wrapped) = 0 OR
      NEW.mldsa_private_key_wrap_key_id IS NULL OR
      (NEW.mldsa_private_key_wrap_key_id IS NOT OLD.mldsa_private_key_wrap_key_id AND
        NEW.mldsa_private_key_wrapped IS OLD.mldsa_private_key_wrapped) OR
      ((NEW.mldsa_private_key_wrap_key_id IS NOT OLD.mldsa_private_key_wrap_key_id OR
        NEW.mldsa_private_key_wrapped IS NOT OLD.mldsa_private_key_wrapped) AND
        NEW.mldsa_private_key_wrap_key_id IS NOT (
          SELECT new_write_key_id FROM identity_write_generation WHERE singleton = 1
        ))
    ) THEN RAISE(ABORT, 'identity-write-fence') END;
  END;
  CREATE TRIGGER identity_write_delete BEFORE DELETE ON device_identities BEGIN
    SELECT RAISE(ABORT, 'identity-write-fence');
  END;
  CREATE TRIGGER identity_generation_no_insert BEFORE INSERT ON identity_write_generation BEGIN
    SELECT RAISE(ABORT, 'identity-write-fence');
  END;
  CREATE TRIGGER identity_generation_advance BEFORE UPDATE ON identity_write_generation BEGIN
    SELECT CASE WHEN NEW.generation != OLD.generation + 1 OR
      length(NEW.new_write_key_id) = 0
    THEN RAISE(ABORT, 'identity-write-fence') END;
  END;
  CREATE TRIGGER identity_generation_no_delete BEFORE DELETE ON identity_write_generation BEGIN
    SELECT RAISE(ABORT, 'identity-write-fence');
  END;
  INSERT INTO identity_write_receipts VALUES ('activation', 1);
  UPDATE schema_meta SET schema_version = 7 WHERE meta_key = 'primary';
  PRAGMA user_version = 7;
`;

const roots: string[] = [];
const secondaryConnections: DatabaseSync[] = [];
const fixtureKeys: Buffer[] = [];

function fixture(): { old: DatabaseSync; admin: DatabaseSync; databasePath: string } {
  const stateDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "identity-v7-fence-")));
  roots.push(stateDir);
  const opened = openOpenClawStateDatabase({ env: { OPENCLAW_STATE_DIR: stateDir } });
  const { DatabaseSync } = requireNodeSqlite();
  const admin = new DatabaseSync(opened.path);
  secondaryConnections.push(admin);
  return { old: opened.db, admin, databasePath: opened.path };
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
  it("leaves the ordinary product database at v6 without activation", () => {
    const { old } = fixture();
    expect(OPENCLAW_STATE_SCHEMA_VERSION).toBe(6);
    expect(old.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
    expect(
      old
        .prepare(
          "SELECT name FROM pragma_table_info('device_identities') WHERE name = 'write_generation'",
        )
        .get(),
    ).toBeUndefined();
    insertSixColumnIdentity(old, "apple-mldsa65-primary");
    expect(old.prepare("SELECT count(*) AS n FROM device_identities").get()).toEqual({ n: 1 });
  });

  it("fences the current Node store on an already-open v6 handle", () => {
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
      const staleWriter = generateStoredDeviceIdentity(1_700_000_000_001, provider, {
        identityKey: "stale-writer",
      });
      expect(() =>
        insertStoredDeviceIdentityIfAbsent(staleWriter, {
          path: databasePath,
          identityKey: "stale-writer",
          wrappingKeyProvider: provider,
        }),
      ).toThrow(/identity-write-fence/);
      expect(admin.prepare("SELECT count(*) AS n FROM device_identities").get()).toEqual({ n: 1 });
    } finally {
      key.fill(0);
    }
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
    expect(() => openOpenClawStateDatabase({ path: databasePath })).toThrow(
      /newer schema version 7/,
    );
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
    expect(rollbackAdmin.prepare("PRAGMA user_version").get()).toEqual({ user_version: 6 });
    expect(
      rollbackAdmin
        .prepare("SELECT schema_version FROM schema_meta WHERE meta_key = 'primary'")
        .get(),
    ).toEqual({
      schema_version: 6,
    });
    expect(
      rollbackAdmin
        .prepare(
          "SELECT name FROM pragma_table_info('device_identities') WHERE name = 'write_generation'",
        )
        .get(),
    ).toBeUndefined();
    expect(
      rollbackAdmin
        .prepare("SELECT name FROM sqlite_schema WHERE name = 'identity_write_generation'")
        .get(),
    ).toBeUndefined();
    expect(
      rollbackAdmin
        .prepare(
          "SELECT name FROM sqlite_schema WHERE name = 'identity_write_receipts' OR name LIKE 'identity_write_%' OR name LIKE 'identity_generation_%'",
        )
        .all(),
    ).toEqual([]);
    expect(
      rollbackAdmin.prepare("SELECT * FROM device_identities WHERE identity_key = 'primary'").get(),
    ).toEqual(beforeRow);
    insertSixColumnIdentity(rollbackOld, "apple-mldsa65-primary");
  });
});
