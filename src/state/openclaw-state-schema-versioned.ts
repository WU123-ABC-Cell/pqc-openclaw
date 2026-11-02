import type { DatabaseSync } from "node:sqlite";
import { readSqliteUserVersion } from "../infra/sqlite-user-version.js";
import { OPENCLAW_STATE_SCHEMA_SQL } from "./openclaw-state-schema.js";

function withoutMarkedBlock(sql: string, name: string): string {
  const startMarker = `-- BEGIN ${name}`;
  const endMarker = `-- END ${name}`;
  const start = sql.indexOf(startMarker);
  const end = sql.indexOf(endMarker);
  if (
    start < 0 ||
    end <= start ||
    sql.includes(startMarker, start + startMarker.length) ||
    sql.includes(endMarker, end + endMarker.length)
  ) {
    throw new Error(`Canonical state schema is missing one ${name} block.`);
  }
  const after = sql.indexOf("\n", end + endMarker.length);
  return sql.slice(0, start) + sql.slice(after < 0 ? sql.length : after + 1);
}

const V6_SCHEMA_SQL = withoutMarkedBlock(
  withoutMarkedBlock(OPENCLAW_STATE_SCHEMA_SQL, "IDENTITY_WRITE_V7_COLUMNS"),
  "IDENTITY_WRITE_V7_OBJECTS",
);

export function canonicalStateSchemaSqlForVersion(version: 6 | 7): string {
  return version === 7 ? OPENCLAW_STATE_SCHEMA_SQL : V6_SCHEMA_SQL;
}

export function ordinaryStateSchemaVersion(db: DatabaseSync): 6 | 7 {
  return readSqliteUserVersion(db) === 7 ? 7 : 6;
}

export function identityWriteV7ObjectsSql(): string {
  const start = "-- BEGIN IDENTITY_WRITE_V7_OBJECTS";
  const end = "-- END IDENTITY_WRITE_V7_OBJECTS";
  return OPENCLAW_STATE_SCHEMA_SQL.slice(
    OPENCLAW_STATE_SCHEMA_SQL.indexOf(start) + start.length,
    OPENCLAW_STATE_SCHEMA_SQL.indexOf(end),
  );
}
