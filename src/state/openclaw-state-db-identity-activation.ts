import type { DatabaseSync } from "node:sqlite";
import { readSqliteUserVersion } from "../infra/sqlite-user-version.js";
import { assertOpenClawStateDatabaseForMaintenance } from "./openclaw-state-db-maintenance.js";
import { markCurrentStateSchemaVersion } from "./openclaw-state-db-schema-repair.js";
import { identityWriteV7ObjectsSql } from "./openclaw-state-schema-versioned.js";

/** Caller holds the identity coordinator and an outer, top-level IMMEDIATE transaction. */
export function activateIdentityWriteSchemaInTransaction(
  db: DatabaseSync,
  pathname: string,
  receiptId: string,
  keyId: string,
): void {
  if (!db.isTransaction) {
    throw new Error("Identity write activation requires a SQLite transaction.");
  }
  const version = readSqliteUserVersion(db);
  if (version !== 6 && version !== 7) {
    throw new Error("Identity write activation requires state schema v6 or dormant v7.");
  }
  if (version === 6) {
    db.exec(`
      ALTER TABLE device_identities ADD COLUMN write_generation INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE device_identities ADD COLUMN write_revision INTEGER NOT NULL DEFAULT 0;
    `);
    db.exec(identityWriteV7ObjectsSql());
  }
  const owner = db.prepare("SELECT 1 FROM identity_write_generation WHERE singleton = 1").get();
  if (owner) {
    throw new Error("Identity write generation is already active.");
  }
  db.exec("UPDATE device_identities SET write_generation = 1, write_revision = 0;");
  db.prepare(
    "INSERT INTO identity_write_generation (singleton, generation, new_write_key_id) VALUES (1, 1, ?)",
  ).run(keyId);
  db.prepare(
    "INSERT INTO identity_write_receipts (receipt_id, generation, new_write_key_id) VALUES (?, 1, ?)",
  ).run(receiptId, keyId);
  markCurrentStateSchemaVersion(db, { targetVersion: 7 });
  assertOpenClawStateDatabaseForMaintenance(db, { pathname });
}
