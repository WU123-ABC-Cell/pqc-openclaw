import type { DatabaseSync } from "node:sqlite";
import type { Selectable } from "kysely";
import type { DB } from "../state/openclaw-state-db.generated.js";
import { DeviceIdentityStorageError } from "./device-identity-store.crypto.js";
import { readSqliteUserVersion } from "./sqlite-user-version.js";

type IdentityRow = Selectable<DB["device_identities"]>;

/** Read the write owner inside the caller's SQLite write transaction. */
export function activeIdentityWriteGeneration(
  db: DatabaseSync,
): { generation: number; newWriteKeyId: string } | null {
  const row = db
    .prepare(
      "SELECT generation, new_write_key_id FROM identity_write_generation WHERE singleton = 1",
    )
    .get();
  if (!row) {
    return null;
  }
  if (
    !Number.isSafeInteger(row.generation) ||
    Number(row.generation) <= 0 ||
    typeof row.new_write_key_id !== "string" ||
    row.new_write_key_id.length === 0
  ) {
    throw new DeviceIdentityStorageError("SQLite identity write generation is invalid.");
  }
  return { generation: Number(row.generation), newWriteKeyId: row.new_write_key_id };
}

/** Apply the current generation and monotonic row revision before SQLite's fence validates it. */
export function identityRowForWrite(
  db: DatabaseSync,
  desired: IdentityRow,
  previous?: IdentityRow,
): IdentityRow {
  if (readSqliteUserVersion(db) < 7) {
    // v6 must retain its exact ten-column identity table for older native clients.
    const legacy = { ...desired };
    delete (legacy as Partial<IdentityRow>).write_generation;
    delete (legacy as Partial<IdentityRow>).write_revision;
    return legacy;
  }
  if (
    previous &&
    (!Number.isSafeInteger(previous.write_generation) ||
      previous.write_generation < 0 ||
      !Number.isSafeInteger(previous.write_revision) ||
      previous.write_revision < 0)
  ) {
    throw new DeviceIdentityStorageError("SQLite identity write metadata is invalid.");
  }
  const revision = previous ? previous.write_revision + 1 : 0;
  if (!Number.isSafeInteger(revision)) {
    throw new DeviceIdentityStorageError("SQLite identity write revision is exhausted.");
  }
  const owner = activeIdentityWriteGeneration(db);
  if (!owner && previous && previous.write_generation > 0) {
    throw new DeviceIdentityStorageError("SQLite identity write generation is missing.");
  }
  return {
    ...desired,
    write_generation: owner?.generation ?? previous?.write_generation ?? 0,
    write_revision: revision,
  };
}
