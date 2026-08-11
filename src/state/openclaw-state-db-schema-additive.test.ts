// PQC 2.1.3 + 2.2.1: device_identities grows four ML-DSA-65 / wrap columns.
// The additive migration must (a) leave the legacy six columns untouched,
// (b) create the four new columns on fresh installs, (c) ADD COLUMN them onto
// pre-existing databases without losing rows, and (d) accept null/wrapped
// payloads that the device-identity store will eventually write.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { requireNodeSqlite } from "../infra/node-sqlite.js";
import { ensureAdditiveStateColumns } from "./openclaw-state-db-schema-additive.js";

const tempRoots: string[] = [];

function createTempStateDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m3-"));
  tempRoots.push(dir);
  return dir;
}

function removeTempRoots(): void {
  while (tempRoots.length > 0) {
    const dir = tempRoots.pop();
    if (!dir) continue;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup; the OS reclaims the temp dir if rm fails.
    }
  }
}

type ColumnInfo = { name: string; notnull: number; pk: number; type: string };

function readColumns(database: ReturnType<typeof requireNodeSqlite>): ColumnInfo[] {
  return database
    .prepare("PRAGMA table_info(device_identities)")
    .all() as ColumnInfo[];
}

function createLegacyDeviceIdentitiesTable(database: ReturnType<typeof requireNodeSqlite>): void {
  // Mirrors the pre-M3 shipped schema. The migration should only ADD COLUMN
  // the four new fields; it must not drop or rename anything that exists.
  database.exec(`
    CREATE TABLE device_identities (
      identity_key TEXT NOT NULL PRIMARY KEY,
      device_id TEXT NOT NULL,
      public_key_pem TEXT NOT NULL,
      private_key_pem TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL
    ) STRICT;
  `);
}

beforeEach(() => {
  tempRoots.length = 0;
});

afterEach(() => {
  removeTempRoots();
});

describe("device_identities PQC columns (whitepaper 2.1.3 + 2.2.1)", () => {
  it("adds the four ML-DSA-65 / wrap columns to a fresh database", () => {
    const { DatabaseSync } = requireNodeSqlite();
    const database = new DatabaseSync(":memory:");
    database.exec(`
      CREATE TABLE device_identities (
        identity_key TEXT NOT NULL PRIMARY KEY,
        device_id TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
      ) STRICT;
    `);

    ensureAdditiveStateColumns(database);

    const names = readColumns(database).map((row) => row.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "mldsa_public_key_pem",
        "mldsa_private_key_pem",
        "mldsa_private_key_wrapped",
        "mldsa_private_key_wrap_key_id",
      ]),
    );
  });

  it("preserves existing rows when ADD COLUMN runs against a legacy database", () => {
    const { DatabaseSync } = requireNodeSqlite();
    const stateDir = createTempStateDir();
    const dbPath = path.join(stateDir, "state.db");
    const database = new DatabaseSync(dbPath);
    createLegacyDeviceIdentitiesTable(database);
    const now = Date.now();
    database
      .prepare(
        `INSERT INTO device_identities
           (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        "primary",
        "0".repeat(64),
        "MLDSA65-PUBLIC-KEY:legacy",
        "MLDSA65-SECRET-KEY:legacy",
        now,
        now,
      );
    database.close();

    const reopened = new DatabaseSync(dbPath);
    try {
      ensureAdditiveStateColumns(reopened);
      const row = reopened
        .prepare(
          "SELECT device_id, public_key_pem, private_key_pem, mldsa_public_key_pem, mldsa_private_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = ?",
        )
        .get("primary") as {
        device_id: string;
        public_key_pem: string;
        private_key_pem: string;
        mldsa_public_key_pem: string | null;
        mldsa_private_key_pem: string | null;
        mldsa_private_key_wrapped: Uint8Array | null;
        mldsa_private_key_wrap_key_id: string | null;
      };
      expect(row.device_id).toBe("0".repeat(64));
      expect(row.public_key_pem).toBe("MLDSA65-PUBLIC-KEY:legacy");
      expect(row.private_key_pem).toBe("MLDSA65-SECRET-KEY:legacy");
      // Legacy rows stay with NULL on the new columns; the device-identity
      // store backfills them on first read after the migration.
      expect(row.mldsa_public_key_pem).toBeNull();
      expect(row.mldsa_private_key_pem).toBeNull();
      expect(row.mldsa_private_key_wrapped).toBeNull();
      expect(row.mldsa_private_key_wrap_key_id).toBeNull();
    } finally {
      reopened.close();
    }
  });

  it("treats ensureAdditiveStateColumns as idempotent across repeated calls", () => {
    const { DatabaseSync } = requireNodeSqlite();
    const database = new DatabaseSync(":memory:");
    createLegacyDeviceIdentitiesTable(database);

    ensureAdditiveStateColumns(database);
    const columnsAfterFirstPass = readColumns(database)
      .map((row) => row.name)
      .sort();
    ensureAdditiveStateColumns(database);
    const columnsAfterSecondPass = readColumns(database)
      .map((row) => row.name)
      .sort();

    expect(columnsAfterFirstPass).toEqual(
      expect.arrayContaining([
        "mldsa_public_key_pem",
        "mldsa_private_key_pem",
        "mldsa_private_key_wrapped",
        "mldsa_private_key_wrap_key_id",
      ]),
    );
    expect(columnsAfterSecondPass).toEqual(columnsAfterFirstPass);

    // The 6 base columns must still be present and unchanged after the second pass.
    expect(columnsAfterSecondPass).toEqual(
      expect.arrayContaining([
        "created_at_ms",
        "device_id",
        "identity_key",
        "private_key_pem",
        "public_key_pem",
        "updated_at_ms",
      ]),
    );
  });

  it("accepts a row that uses the wrapped (ciphertext) form for mldsa_private_key", () => {
    const { DatabaseSync } = requireNodeSqlite();
    const database = new DatabaseSync(":memory:");
    createLegacyDeviceIdentitiesTable(database);
    ensureAdditiveStateColumns(database);

    const now = Date.now();
    const ciphertext = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);
    database
      .prepare(
        `INSERT INTO device_identities
           (identity_key, device_id, public_key_pem, private_key_pem,
            mldsa_public_key_pem, mldsa_private_key_pem, mldsa_private_key_wrapped,
            mldsa_private_key_wrap_key_id, created_at_ms, updated_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        "primary",
        "a".repeat(64),
        "MLDSA65-PUBLIC-KEY:new",
        "MLDSA65-SECRET-KEY:new",
        "MLDSA65-PUBLIC-KEY:new",
        // plaintext intentionally NULL — the wrapped form replaces it.
        null,
        ciphertext,
        "wrap-key-2026-08",
        now,
        now,
      );

    const row = database
      .prepare(
        "SELECT mldsa_public_key_pem, mldsa_private_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = ?",
      )
      .get("primary") as {
      mldsa_public_key_pem: string | null;
      mldsa_private_key_pem: string | null;
      mldsa_private_key_wrapped: Uint8Array | null;
      mldsa_private_key_wrap_key_id: string | null;
    };
    expect(row.mldsa_public_key_pem).toBe("MLDSA65-PUBLIC-KEY:new");
    expect(row.mldsa_private_key_pem).toBeNull();
    expect(row.mldsa_private_key_wrapped).not.toBeNull();
    expect(Array.from(row.mldsa_private_key_wrapped ?? new Uint8Array())).toEqual(
      Array.from(ciphertext),
    );
    expect(row.mldsa_private_key_wrap_key_id).toBe("wrap-key-2026-08");
  });
});
