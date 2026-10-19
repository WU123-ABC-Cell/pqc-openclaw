import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { encodeBase64UrlKey, FileKeyring } from "../security/keyring-provider.js";
import {
  serializeWrappedSecret,
  type WrappingKeyProvider,
  wrapSecret,
} from "../security/secret-wrapping.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
  OPENCLAW_STATE_SCHEMA_VERSION,
} from "../state/openclaw-state-db.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  preflightDeviceIdentityPopulationReadOnly,
} from "./device-identity-store.js";
import { preflightDeviceIdentityReadinessReadOnly } from "./device-identity.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  generateMlDsa65KeyPair,
} from "./mldsa65-key-storage.js";
import { requireNodeSqlite } from "./node-sqlite.js";

const directories: string[] = [];
const keys: Buffer[] = [];

function fixture() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "identity-preflight-"));
  directories.push(stateDir);
  return {
    path: path.join(stateDir, "state", "openclaw.sqlite"),
    env: { ...process.env, OPENCLAW_STATE_DIR: stateDir },
  };
}

function keyring(activeId: string, entries: Map<string, Buffer>): WrappingKeyProvider {
  return {
    getActiveKey: () => ({ key: entries.get(activeId)!, keyId: activeId }),
    getKeyById: (id) => entries.get(id) ?? null,
  };
}

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
  for (const key of keys.splice(0)) {
    key.fill(0);
  }
  for (const dir of directories.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

it("does not create a missing state database", async () => {
  const options = fixture();
  expect(await preflightDeviceIdentityPopulationReadOnly(options)).toEqual({
    databaseExists: false,
    rows: [],
    allRowsVerified: false,
  });
  expect(fs.existsSync(options.path)).toBe(false);
});

it("keeps an absent wrapping key and database absent during the combined read-only preflight", async () => {
  const options = fixture();
  const report = await preflightDeviceIdentityReadinessReadOnly({
    ...options,
    env: {
      ...options.env,
      OPENCLAW_WRAP_KEY_FILE: undefined,
      OPENCLAW_WRAP_KEY_OS_SERVICE: undefined,
      OPENCLAW_WRAP_KEY_OS_ACCOUNT: undefined,
    },
  });
  expect(report).toEqual({
    population: { databaseExists: false, rows: [], allRowsVerified: false },
    provider: { status: "blocked", reason: "not-configured" },
  });
  expect(fs.existsSync(options.path)).toBe(false);
  expect(fs.existsSync(path.join(path.dirname(path.dirname(options.path)), "wrap-key.b64"))).toBe(
    false,
  );
});

it("checks the existing identity and configured new-write file key without changing either", async () => {
  const options = fixture();
  const keyPath = path.join(path.dirname(path.dirname(options.path)), "configured-wrap.key");
  const key = randomBytes(32);
  keys.push(key);
  fs.writeFileSync(keyPath, encodeBase64UrlKey(key), { mode: 0o600 });
  const provider = new FileKeyring(keyPath, "configured-key");
  insertStoredDeviceIdentityIfAbsent(generateStoredDeviceIdentity(1_700_000_000_000, provider), {
    ...options,
    wrappingKeyProvider: provider,
  });
  closeOpenClawStateDatabaseForTest();
  const beforeDatabase = fs.readFileSync(options.path);
  const beforeKey = fs.readFileSync(keyPath);
  const report = await preflightDeviceIdentityReadinessReadOnly({
    ...options,
    env: {
      ...options.env,
      OPENCLAW_WRAP_KEY_FILE: keyPath,
      OPENCLAW_WRAP_KEY_ID: "configured-key",
      OPENCLAW_WRAP_KEY_OS_SERVICE: undefined,
      OPENCLAW_WRAP_KEY_OS_ACCOUNT: undefined,
    },
  });
  expect(report).toEqual({
    population: {
      databaseExists: true,
      rows: [
        {
          identityKey: "primary",
          kind: "node-v2",
          status: "verified",
          wrappingKeyId: "configured-key",
        },
      ],
      allRowsVerified: true,
    },
    provider: { status: "verified", activeKeyId: "configured-key" },
  });
  expect(fs.readFileSync(options.path)).toEqual(beforeDatabase);
  expect(fs.readFileSync(keyPath)).toEqual(beforeKey);
});

it("authenticates every Node row with its historical key and reports unavailable keys", async () => {
  const options = fixture();
  const first = randomBytes(32);
  const second = randomBytes(32);
  keys.push(first, second);
  const entries = new Map([
    ["first", first],
    ["second", second],
  ]);
  for (const id of ["first", "second"]) {
    const provider = keyring(id, entries);
    insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(1_700_000_000_000, provider, { identityKey: id }),
      { ...options, identityKey: id, wrappingKeyProvider: provider },
    );
  }
  closeOpenClawStateDatabaseForTest();
  const before = fs.readFileSync(options.path);
  const report = await preflightDeviceIdentityPopulationReadOnly({
    ...options,
    wrappingKeyProvider: keyring("first", entries),
  });
  expect(report).toEqual({
    databaseExists: true,
    rows: [
      { identityKey: "first", kind: "node-v2", status: "verified", wrappingKeyId: "first" },
      { identityKey: "second", kind: "node-v2", status: "verified", wrappingKeyId: "second" },
    ],
    allRowsVerified: true,
  });
  expect(fs.readFileSync(options.path)).toEqual(before);

  entries.delete("second");
  const missing = await preflightDeviceIdentityPopulationReadOnly({
    ...options,
    wrappingKeyProvider: keyring("first", entries),
  });
  expect(missing.rows[1]).toEqual({
    identityKey: "second",
    kind: "node-v2",
    status: "blocked",
    reason: "key-unavailable",
    wrappingKeyId: "second",
  });
  expect(missing.allRowsVerified).toBe(false);
  expect(fs.readFileSync(options.path)).toEqual(before);
});

it("keeps Apple seed rows pending native proof and blocks contradictory Node columns", async () => {
  const options = fixture();
  const wrappingKey = randomBytes(32);
  keys.push(wrappingKey);
  const entries = new Map([["active", wrappingKey]]);
  const provider = keyring("active", entries);
  insertStoredDeviceIdentityIfAbsent(generateStoredDeviceIdentity(1_700_000_000_000, provider), {
    ...options,
    wrappingKeyProvider: provider,
  });
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(options.path);
  try {
    const publicKey = generateMlDsa65KeyPair().publicKey;
    const applePublic = `MLDSA65-PUBLIC-KEY:${Buffer.from(publicKey).toString("base64")}`;
    const appleSeed = `MLDSA65-SEED:${randomBytes(32).toString("base64")}`;
    const deviceId = createHash("sha256").update(publicKey).digest("hex");
    database
      .prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run("apple-mldsa65-primary", deviceId, applePublic, appleSeed, 1, 1);
    database
      .prepare("UPDATE device_identities SET private_key_pem = ? WHERE identity_key = ?")
      .run("contradictory-plaintext", "primary");
  } finally {
    database.close();
  }
  const report = await preflightDeviceIdentityPopulationReadOnly({
    ...options,
    wrappingKeyProvider: provider,
  });
  expect(report.rows).toEqual([
    {
      identityKey: "apple-mldsa65-primary",
      kind: "apple-seed",
      status: "needs-native-verification",
    },
    {
      identityKey: "primary",
      kind: "node-v2",
      status: "blocked",
      reason: "invalid-row",
      wrappingKeyId: "active",
    },
  ]);
  expect(report.allRowsVerified).toBe(false);
});

it("distinguishes plaintext and authenticated legacy envelopes without rewriting either row", async () => {
  const options = fixture();
  const secret = randomBytes(32);
  keys.push(secret);
  const provider = keyring("legacy", new Map([["legacy", secret]]));
  for (const identityKey of ["plaintext", "legacy"]) {
    insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(1_700_000_000_000, undefined, {
        identityKey,
        allowPlaintextPrivateKey: true,
      }),
      { ...options, identityKey },
    );
  }
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(options.path);
  try {
    const row = database
      .prepare("SELECT private_key_pem FROM device_identities WHERE identity_key = ?")
      .get("legacy") as { private_key_pem: string };
    const raw = decodeMlDsa65SecretKey(row.private_key_pem);
    const envelope = serializeWrappedSecret(wrapSecret(Buffer.from(raw), provider));
    raw.fill(0);
    database
      .prepare(
        "UPDATE device_identities SET private_key_pem = '', mldsa_private_key_pem = NULL, mldsa_private_key_wrapped = ?, mldsa_private_key_wrap_key_id = ? WHERE identity_key = ?",
      )
      .run(Buffer.from(envelope), "legacy", "legacy");
  } finally {
    database.close();
  }
  const before = fs.readFileSync(options.path);
  const report = await preflightDeviceIdentityPopulationReadOnly({
    ...options,
    wrappingKeyProvider: provider,
  });
  expect(report.rows).toEqual([
    { identityKey: "legacy", kind: "node-v1", status: "needs-upgrade", wrappingKeyId: "legacy" },
    { identityKey: "plaintext", kind: "node-plaintext", status: "needs-upgrade" },
  ]);
  expect(report.allRowsVerified).toBe(false);
  expect(fs.readFileSync(options.path)).toEqual(before);
});

it("reports unsupported envelopes and malformed identity keys without skipping later rows", async () => {
  const options = fixture();
  const secret = randomBytes(32);
  keys.push(secret);
  const provider = keyring("active", new Map([["active", secret]]));
  for (const identityKey of ["future", "malformed", "healthy"]) {
    insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(1_700_000_000_000, provider, { identityKey }),
      { ...options, identityKey, wrappingKeyProvider: provider },
    );
  }
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(options.path);
  try {
    const row = database
      .prepare("SELECT mldsa_private_key_wrapped FROM device_identities WHERE identity_key = ?")
      .get("future") as { mldsa_private_key_wrapped: Uint8Array };
    const serialized = Buffer.from(row.mldsa_private_key_wrapped).toString("utf8");
    const envelope = JSON.parse(Buffer.from(serialized, "base64url").toString("utf8"));
    envelope.version = 3;
    const future = Buffer.from(Buffer.from(JSON.stringify(envelope)).toString("base64url"));
    database
      .prepare("UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = ?")
      .run(future, "future");
    database
      .prepare("UPDATE device_identities SET identity_key = ? WHERE identity_key = ?")
      .run(" malformed ", "malformed");
  } finally {
    database.close();
  }
  const report = await preflightDeviceIdentityPopulationReadOnly({
    ...options,
    wrappingKeyProvider: provider,
  });
  expect(report.rows).toHaveLength(3);
  expect(report.rows).toEqual([
    { identityKey: " malformed ", kind: "unknown", status: "blocked", reason: "invalid-row" },
    { identityKey: "future", kind: "unknown", status: "blocked", reason: "unsupported-envelope" },
    { identityKey: "healthy", kind: "node-v2", status: "verified", wrappingKeyId: "active" },
  ]);
  expect(report.allRowsVerified).toBe(false);
});

it("keeps every reserved Apple seed pending native proof and rejects malformed or near-match rows", async () => {
  const options = fixture();
  openOpenClawStateDatabase(options);
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(options.path);
  const publicKey = generateMlDsa65KeyPair().publicKey;
  const publicKeyPem = `MLDSA65-PUBLIC-KEY:${Buffer.from(publicKey).toString("base64")}`;
  const seedPem = `MLDSA65-SEED:${randomBytes(32).toString("base64")}`;
  const deviceId = createHash("sha256").update(publicKey).digest("hex");
  const reserved = ["apple-mldsa65-primary", "apple-mldsa65-node", "apple-mldsa65-shareExtension"];
  try {
    const insert = database.prepare(
      "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
    );
    for (const identityKey of [...reserved, "apple-mldsa65-primary-typo"]) {
      insert.run(identityKey, deviceId, publicKeyPem, seedPem, 1, 1);
    }
  } finally {
    database.close();
  }
  const before = fs.readFileSync(options.path);
  const initial = await preflightDeviceIdentityPopulationReadOnly(options);
  for (const identityKey of reserved) {
    expect(initial.rows.find((row) => row.identityKey === identityKey)).toEqual({
      identityKey,
      kind: "apple-seed",
      status: "needs-native-verification",
    });
  }
  expect(initial.rows.find((row) => row.identityKey === "apple-mldsa65-primary-typo")).toEqual({
    identityKey: "apple-mldsa65-primary-typo",
    kind: "node-plaintext",
    status: "blocked",
    reason: "invalid-row",
  });
  expect(initial.allRowsVerified).toBe(false);
  expect(fs.readFileSync(options.path)).toEqual(before);

  const corrupted = new DatabaseSync(options.path);
  try {
    corrupted
      .prepare("UPDATE device_identities SET private_key_pem = ? WHERE identity_key = ?")
      .run(`MLDSA65-SEED:${randomBytes(31).toString("base64")}`, "apple-mldsa65-node");
    corrupted
      .prepare("UPDATE device_identities SET device_id = ? WHERE identity_key = ?")
      .run("0".repeat(64), "apple-mldsa65-shareExtension");
  } finally {
    corrupted.close();
  }
  const damaged = await preflightDeviceIdentityPopulationReadOnly(options);
  for (const identityKey of ["apple-mldsa65-node", "apple-mldsa65-shareExtension"]) {
    expect(damaged.rows.find((row) => row.identityKey === identityKey)).toEqual({
      identityKey,
      kind: "apple-seed",
      status: "blocked",
      reason: "invalid-row",
    });
  }
  expect(damaged.rows.find((row) => row.identityKey === "apple-mldsa65-primary")?.status).toBe(
    "needs-native-verification",
  );
});

it("classifies a synthetic version-0 six-column table without migrating it", async () => {
  const options = fixture();
  fs.mkdirSync(path.dirname(options.path), { recursive: true });
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(options.path);
  const node = generateStoredDeviceIdentity(1_700_000_000_000, undefined, {
    allowPlaintextPrivateKey: true,
  });
  const publicKey = decodeMlDsa65PublicKey(node.publicKeyPem);
  const applePublic = `MLDSA65-PUBLIC-KEY:${Buffer.from(publicKey).toString("base64")}`;
  // This syntactic Apple row does not prove a native seed/public pair.
  const appleSeed = `MLDSA65-SEED:${randomBytes(32).toString("base64")}`;
  try {
    database.exec(`
      CREATE TABLE device_identities (
        identity_key TEXT NOT NULL PRIMARY KEY,
        device_id TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX idx_device_identities_device
        ON device_identities(device_id, updated_at_ms DESC);
    `);
    const insert = database.prepare(
      "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
    );
    insert.run("primary", node.deviceId, node.publicKeyPem, node.privateKeyPem, 1, 1);
    insert.run("apple-mldsa65-primary", node.deviceId, applePublic, appleSeed, 1, 1);
  } finally {
    database.close();
  }
  const before = fs.readFileSync(options.path);
  expect(await preflightDeviceIdentityPopulationReadOnly(options)).toEqual({
    databaseExists: true,
    rows: [
      {
        identityKey: "apple-mldsa65-primary",
        kind: "apple-seed",
        status: "needs-native-verification",
      },
      { identityKey: "primary", kind: "node-plaintext", status: "needs-upgrade" },
    ],
    allRowsVerified: false,
  });
  expect(fs.readFileSync(options.path)).toEqual(before);
  const inspected = new DatabaseSync(options.path, { readOnly: true });
  try {
    expect(inspected.prepare("PRAGMA user_version").get()).toEqual({ user_version: 0 });
    expect(inspected.prepare("PRAGMA table_info(device_identities)").all()).toHaveLength(6);
  } finally {
    inspected.close();
  }
});

it("rejects an incomplete current-version schema without repairing it", async () => {
  const options = fixture();
  openOpenClawStateDatabase(options);
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(options.path);
  try {
    expect(database.prepare("PRAGMA user_version").get()).toEqual({
      user_version: OPENCLAW_STATE_SCHEMA_VERSION,
    });
    expect(
      database.prepare("SELECT role FROM schema_meta WHERE meta_key = 'primary'").get(),
    ).toEqual({ role: "global" });
    database.exec("ALTER TABLE device_identities DROP COLUMN mldsa_private_key_wrap_key_id;");
  } finally {
    database.close();
  }
  const before = fs.readFileSync(options.path);
  await expect(preflightDeviceIdentityPopulationReadOnly(options)).rejects.toThrow(
    /device_identities/u,
  );
  expect(fs.readFileSync(options.path)).toEqual(before);
});

it("blocks partial, contradictory, and tampered v2 rows without changing the inspected database", async () => {
  const options = fixture();
  const key = randomBytes(32);
  keys.push(key);
  const provider = keyring("active", new Map([["active", key]]));
  insertStoredDeviceIdentityIfAbsent(generateStoredDeviceIdentity(1_700_000_000_000, provider), {
    ...options,
    wrappingKeyProvider: provider,
  });
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const database = new DatabaseSync(options.path);
  try {
    const original = database
      .prepare(
        "SELECT device_id, private_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = ?",
      )
      .get("primary") as {
      device_id: string;
      private_key_pem: string;
      mldsa_private_key_wrapped: Uint8Array;
      mldsa_private_key_wrap_key_id: string;
    };
    const serialized = Buffer.from(original.mldsa_private_key_wrapped).toString("utf8");
    const envelope = JSON.parse(Buffer.from(serialized, "base64url").toString("utf8"));
    const ciphertext = Buffer.from(envelope.ciphertext, "base64url");
    if (ciphertext.length === 0) {
      throw new Error("Expected a nonempty encrypted identity payload");
    }
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    envelope.ciphertext = ciphertext.toString("base64url");
    const tampered = Buffer.from(Buffer.from(JSON.stringify(envelope)).toString("base64url"));
    const cases = [
      {
        column: "mldsa_private_key_wrap_key_id",
        value: null,
        expected: { kind: "unknown", reason: "invalid-row" },
      },
      {
        column: "mldsa_private_key_wrap_key_id",
        value: "other-id",
        expected: { kind: "unknown", reason: "invalid-row" },
      },
      {
        column: "mldsa_private_key_wrapped",
        value: tampered,
        expected: { kind: "node-v2" },
      },
      {
        column: "device_id",
        value: "0".repeat(64),
        expected: { kind: "node-v2" },
      },
      {
        column: "private_key_pem",
        value: "contradictory-plaintext",
        expected: { kind: "node-v2", reason: "invalid-row" },
      },
    ] as const;
    for (const candidate of cases) {
      database
        .prepare(`UPDATE device_identities SET ${candidate.column} = ? WHERE identity_key = ?`)
        .run(candidate.value, "primary");
      const before = fs.readFileSync(options.path);
      const report = await preflightDeviceIdentityPopulationReadOnly({
        ...options,
        wrappingKeyProvider: provider,
      });
      expect(report.rows).toHaveLength(1);
      expect(report.rows[0]).toMatchObject({
        identityKey: "primary",
        status: "blocked",
        ...candidate.expected,
      });
      expect(report.allRowsVerified).toBe(false);
      expect(fs.readFileSync(options.path)).toEqual(before);
      database
        .prepare(`UPDATE device_identities SET ${candidate.column} = ? WHERE identity_key = ?`)
        .run(original[candidate.column], "primary");
    }
  } finally {
    database.close();
  }
  const restored = await preflightDeviceIdentityPopulationReadOnly({
    ...options,
    wrappingKeyProvider: provider,
  });
  expect(restored.rows).toEqual([
    { identityKey: "primary", kind: "node-v2", status: "verified", wrappingKeyId: "active" },
  ]);
  expect(restored.allRowsVerified).toBe(true);
});
