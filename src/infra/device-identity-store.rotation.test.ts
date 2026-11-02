import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { CompositeKeyring, EnvKeyring, FileKeyring } from "../security/keyring-provider.js";
import {
  closeOpenClawStateDatabaseForTest,
  getOpenClawStateDatabaseIfOpen,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import { identityWriteV7ObjectsSql } from "../state/openclaw-state-schema-versioned.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
} from "./device-identity-store.js";
import {
  activateDeviceIdentityWriteGeneration,
  rotateDeviceIdentityWrappingKey,
} from "./device-identity.js";

const roots: string[] = [];
const providers: EnvKeyring[] = [];

function ring(id: string, value: number): EnvKeyring {
  const provider = new EnvKeyring(
    `ROTATION_TEST_${id}`,
    { [`ROTATION_TEST_${id}`]: Buffer.alloc(32, value).toString("base64url") },
    id,
  );
  providers.push(provider);
  return provider;
}

function fixture() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "identity-rotation-"));
  roots.push(stateDir);
  const options = { env: { OPENCLAW_STATE_DIR: stateDir } };
  const database = openOpenClawStateDatabase(options);
  const old = ring("key-B", 2);
  const historical = ring("key-A", 1);
  const next = ring("key-C", 3);
  const oldRead = new CompositeKeyring([old, historical]);
  const newRead = new CompositeKeyring([next, old, historical]);
  const first = generateStoredDeviceIdentity(1_700_000_000_000, old, { identityKey: "first" });
  const second = generateStoredDeviceIdentity(1_700_000_000_001, historical, {
    identityKey: "second",
  });
  insertStoredDeviceIdentityIfAbsent(first, {
    ...options,
    identityKey: "first",
    wrappingKeyProvider: old,
  });
  insertStoredDeviceIdentityIfAbsent(second, {
    ...options,
    identityKey: "second",
    wrappingKeyProvider: historical,
  });
  closeOpenClawStateDatabaseForTest();
  expect(
    activateDeviceIdentityWriteGeneration("activation", {
      ...options,
      wrappingKeyProvider: oldRead,
    }),
  ).toEqual({ generation: 1, replayed: false, databaseState: "current" });
  const firstSecret = readStoredDeviceIdentity({
    ...options,
    identityKey: "first",
    wrappingKeyProvider: oldRead,
  })?.privateKeyPem;
  const secondSecret = readStoredDeviceIdentity({
    ...options,
    identityKey: "second",
    wrappingKeyProvider: oldRead,
  })?.privateKeyPem;
  closeOpenClawStateDatabaseForTest();
  return {
    options,
    databasePath: database.path,
    oldRead,
    newRead,
    old,
    next,
    firstSecret,
    secondSecret,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  closeOpenClawStateDatabaseForTest();
  for (const provider of providers.splice(0)) {
    provider.release();
  }
  for (const root of roots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

it("atomically rotates mixed historical Node rows and preserves identity material", () => {
  const { options, oldRead, newRead, firstSecret, secondSecret } = fixture();
  const admin = openOpenClawStateDatabase(options).db;
  const before = admin.prepare("SELECT * FROM device_identities ORDER BY identity_key").all();
  closeOpenClawStateDatabaseForTest();

  expect(
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-2",
      targetKeyId: "key-C",
      oldKeyring: oldRead,
      newKeyring: newRead,
      options,
    }),
  ).toEqual({ generation: 2, replayed: false, databaseState: "current" });
  const db = openOpenClawStateDatabase(options).db;
  expect(
    db.prepare("SELECT generation, new_write_key_id FROM identity_write_generation").get(),
  ).toEqual({
    generation: 2,
    new_write_key_id: "key-C",
  });
  expect(
    db.prepare("SELECT * FROM identity_write_receipts WHERE receipt_id='rotation-2'").get(),
  ).toEqual({
    receipt_id: "rotation-2",
    generation: 2,
    new_write_key_id: "key-C",
  });
  const after = db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all() as Array<{
    identity_key: string;
    write_generation: number;
    write_revision: number;
    mldsa_private_key_wrap_key_id: string;
    device_id: string;
    public_key_pem: string;
  }>;
  expect(after).toHaveLength(2);
  for (const row of after) {
    const original = before.find((candidate) => candidate.identity_key === row.identity_key)!;
    expect(row).toMatchObject({
      write_generation: 2,
      write_revision: 1,
      mldsa_private_key_wrap_key_id: "key-C",
      device_id: original.device_id,
      public_key_pem: original.public_key_pem,
    });
  }
  expect(
    readStoredDeviceIdentity({ ...options, identityKey: "first", wrappingKeyProvider: newRead })
      ?.privateKeyPem,
  ).toBe(firstSecret);
  expect(
    readStoredDeviceIdentity({ ...options, identityKey: "second", wrappingKeyProvider: newRead })
      ?.privateKeyPem,
  ).toBe(secondSecret);
  closeOpenClawStateDatabaseForTest();
  const unavailable = {
    getActiveKey: (): never => {
      throw new Error("key unavailable");
    },
    getKeyById: (): null => null,
  };
  expect(
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-2",
      targetKeyId: "key-C",
      oldKeyring: unavailable,
      newKeyring: unavailable,
      options,
    }),
  ).toEqual({ generation: 2, replayed: true, databaseState: "current" });
  expect(() =>
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-2",
      targetKeyId: "wrong",
      oldKeyring: unavailable,
      newKeyring: unavailable,
      options,
    }),
  ).toThrow(/different target/);
});

it("distinguishes a committed receipt from the current rotation after a later rotation", () => {
  const { options, oldRead, newRead } = fixture();
  rotateDeviceIdentityWrappingKey({
    receiptId: "rotation-2",
    targetKeyId: "key-C",
    oldKeyring: oldRead,
    newKeyring: newRead,
    options,
  });
  const latest = new CompositeKeyring([ring("key-D", 4), newRead]);
  expect(
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-3",
      targetKeyId: "key-D",
      oldKeyring: newRead,
      newKeyring: latest,
      options,
    }),
  ).toEqual({ generation: 3, replayed: false, databaseState: "current" });
  const unavailable = {
    getActiveKey: (): never => {
      throw new Error("key unavailable");
    },
    getKeyById: (): null => null,
  };
  expect(
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-2",
      targetKeyId: "key-C",
      oldKeyring: unavailable,
      newKeyring: unavailable,
      options,
    }),
  ).toEqual({ generation: 2, replayed: true, databaseState: "superseded" });
  expect(activateDeviceIdentityWriteGeneration("activation", options)).toEqual({
    generation: 1,
    replayed: true,
    databaseState: "superseded",
  });
  expect(
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-3",
      targetKeyId: "key-D",
      oldKeyring: unavailable,
      newKeyring: unavailable,
      options,
    }),
  ).toEqual({ generation: 3, replayed: true, databaseState: "current" });
});

it("rolls owner and every row back if new key access fails after rewrapping", () => {
  const { options, oldRead, newRead, next, databasePath } = fixture();
  const db = openOpenClawStateDatabase(options).db;
  const before = db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all();
  closeOpenClawStateDatabaseForTest();
  const originalLookup = next.getKeyById.bind(next);
  let sawNewOwner = false;
  vi.spyOn(next, "getKeyById").mockImplementation((keyId) => {
    const opened = getOpenClawStateDatabaseIfOpen({ path: databasePath });
    if (
      opened?.db.isTransaction &&
      opened.db.prepare("SELECT generation FROM identity_write_generation").get()?.generation === 2
    ) {
      sawNewOwner = true;
      throw new Error("injected-post-write-key-failure");
    }
    return originalLookup(keyId);
  });
  expect(() =>
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-fail",
      targetKeyId: "key-C",
      oldKeyring: oldRead,
      newKeyring: newRead,
      options,
    }),
  ).toThrow(/Cannot authenticate or decrypt device identity/);
  expect(sawNewOwner).toBe(true);
  const reopened = openOpenClawStateDatabase(options).db;
  expect(
    reopened.prepare("SELECT generation, new_write_key_id FROM identity_write_generation").get(),
  ).toEqual({
    generation: 1,
    new_write_key_id: "key-B",
  });
  expect(reopened.prepare("SELECT * FROM device_identities ORDER BY identity_key").all()).toEqual(
    before,
  );
  expect(
    reopened
      .prepare("SELECT * FROM identity_write_receipts WHERE receipt_id='rotation-fail'")
      .all(),
  ).toEqual([]);
});

it("refuses to commit when a prepared file changes after its key was cached", () => {
  const { options, oldRead, databasePath } = fixture();
  const keyPath = path.join(path.dirname(databasePath), "prepared-key.b64");
  fs.writeFileSync(keyPath, Buffer.alloc(32, 3).toString("base64url"), { mode: 0o600 });
  const target = new FileKeyring(keyPath, "key-C");
  const next = new CompositeKeyring([target, oldRead]);
  let changed = false;
  const lookup = next.getKeyById.bind(next);
  vi.spyOn(next, "getKeyById").mockImplementation((keyId) => {
    const opened = getOpenClawStateDatabaseIfOpen({ path: databasePath });
    if (!changed && opened?.db.isTransaction && keyId === "key-C") {
      fs.writeFileSync(keyPath, Buffer.alloc(32, 7).toString("base64url"));
      changed = true;
    }
    return lookup(keyId);
  });
  expect(() =>
    rotateDeviceIdentityWrappingKey({
      receiptId: "changed-file",
      targetKeyId: "key-C",
      oldKeyring: oldRead,
      newKeyring: next,
      options,
    }),
  ).toThrow(/rotation key changed on disk/);
  expect(changed).toBe(true);
  const db = openOpenClawStateDatabase(options).db;
  expect(db.prepare("SELECT generation FROM identity_write_generation").get()).toEqual({
    generation: 1,
  });
  expect(
    db.prepare("SELECT * FROM identity_write_receipts WHERE receipt_id='changed-file'").get(),
  ).toBeUndefined();
  next.release();
});

it.each([
  { generation: 0, revision: 0 },
  { generation: 1, revision: -1 },
])("refuses stale or invalid row write metadata before rotation %#", ({ generation, revision }) => {
  const { options, oldRead, newRead } = fixture();
  const db = openOpenClawStateDatabase(options).db;
  db.exec("DROP TRIGGER identity_write_update;");
  db.prepare(
    "UPDATE device_identities SET write_generation = ?, write_revision = ? WHERE identity_key = 'first'",
  ).run(generation, revision);
  db.exec(identityWriteV7ObjectsSql());
  const before = db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all();
  closeOpenClawStateDatabaseForTest();
  expect(() =>
    rotateDeviceIdentityWrappingKey({
      receiptId: "rotation-invalid",
      targetKeyId: "key-C",
      oldKeyring: oldRead,
      newKeyring: newRead,
      options,
    }),
  ).toThrow(/row write metadata|outside the active generation/);
  const after = openOpenClawStateDatabase(options).db;
  expect(
    after.prepare("SELECT generation, new_write_key_id FROM identity_write_generation").get(),
  ).toEqual({
    generation: 1,
    new_write_key_id: "key-B",
  });
  expect(after.prepare("SELECT * FROM device_identities ORDER BY identity_key").all()).toEqual(
    before,
  );
});

it("refuses rotation when the old provider cannot read a historical row", () => {
  const { options, old, newRead } = fixture();
  expect(() =>
    rotateDeviceIdentityWrappingKey({
      receiptId: "missing-old",
      targetKeyId: "key-C",
      oldKeyring: old,
      newKeyring: newRead,
      options,
    }),
  ).toThrow(/every row to be verified/);
  expect(
    openOpenClawStateDatabase(options)
      .db.prepare("SELECT generation FROM identity_write_generation")
      .get(),
  ).toEqual({ generation: 1 });
});

it("does not advance a generation when the activated identity population is empty", () => {
  const { options, oldRead, newRead } = fixture();
  const db = openOpenClawStateDatabase(options).db;
  db.exec("DROP TRIGGER identity_write_delete;");
  db.exec("DELETE FROM device_identities;");
  db.exec(identityWriteV7ObjectsSql());
  closeOpenClawStateDatabaseForTest();
  expect(() =>
    rotateDeviceIdentityWrappingKey({
      receiptId: "empty-population",
      targetKeyId: "key-C",
      oldKeyring: oldRead,
      newKeyring: newRead,
      options,
    }),
  ).toThrow(/nonempty identity population/);
  expect(
    openOpenClawStateDatabase(options)
      .db.prepare("SELECT generation FROM identity_write_generation")
      .get(),
  ).toEqual({ generation: 1 });
});

it("refuses a validly shaped Apple seed row until native verification exists", () => {
  const { options, oldRead, newRead } = fixture();
  const db = openOpenClawStateDatabase(options).db;
  const publicRaw = Buffer.alloc(1952, 4);
  db.prepare(`INSERT INTO device_identities (
    identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms,
    write_generation, write_revision
  ) VALUES (?, ?, ?, ?, 1, 1, 1, 0)`).run(
    "apple-mldsa65-primary",
    createHash("sha256").update(publicRaw).digest("hex"),
    `MLDSA65-PUBLIC-KEY:${publicRaw.toString("base64")}`,
    `MLDSA65-SEED:${Buffer.alloc(32, 5).toString("base64")}`,
  );
  closeOpenClawStateDatabaseForTest();
  expect(() =>
    rotateDeviceIdentityWrappingKey({
      receiptId: "apple-pending",
      targetKeyId: "key-C",
      oldKeyring: oldRead,
      newKeyring: newRead,
      options,
    }),
  ).toThrow(/native rows first/);
  expect(
    openOpenClawStateDatabase(options)
      .db.prepare("SELECT generation FROM identity_write_generation")
      .get(),
  ).toEqual({ generation: 1 });
});

it("refuses a receipt whose active generation names a different key", () => {
  const { options } = fixture();
  const db = openOpenClawStateDatabase(options).db;
  db.exec("DROP TRIGGER identity_generation_advance;");
  db.prepare(
    "UPDATE identity_write_generation SET new_write_key_id = 'wrong' WHERE singleton = 1",
  ).run();
  db.exec(identityWriteV7ObjectsSql());
  closeOpenClawStateDatabaseForTest();
  expect(() => activateDeviceIdentityWriteGeneration("activation", options)).toThrow(
    /receipt is inconsistent/,
  );
});
