import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { FileKeyring, resetDefaultKeyringCache } from "../security/keyring-provider.js";
import { serializeWrappedSecret, wrapSecret } from "../security/secret-wrapping.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  repairInvalidStoredDeviceIdentity,
  validateStoredDeviceIdentity,
  type StoredDeviceIdentity,
} from "./device-identity-store.js";
import { loadOrCreateDeviceIdentity } from "./device-identity.js";
import { decodeMlDsa65SecretKey } from "./mldsa65-key-storage.js";
import { requireNodeSqlite } from "./node-sqlite.js";
import { repairInvalidCanonicalIdentity } from "./state-migrations.device-identity-repair.js";

const dirs: string[] = [];
const providers: FileKeyring[] = [];
function fixture() {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "identity-pair-")));
  dirs.push(dir);
  const keyPath = path.join(dir, "key");
  fs.writeFileSync(keyPath, Buffer.alloc(32, 7).toString("base64url"), { mode: 0o600 });
  const provider = new FileKeyring(keyPath, "fixture-key");
  providers.push(provider);
  return {
    env: {
      OPENCLAW_STATE_DIR: dir,
      OPENCLAW_WRAP_KEY_FILE: keyPath,
      OPENCLAW_WRAP_KEY_ID: "fixture-key",
    },
    path: path.join(dir, "state", "openclaw.sqlite"),
    wrappingKeyProvider: provider,
  };
}
function plain() {
  return generateStoredDeviceIdentity(1700000000000, undefined, { allowPlaintextPrivateKey: true });
}
function wrap(stored: StoredDeviceIdentity, provider: FileKeyring) {
  const raw = decodeMlDsa65SecretKey(stored.privateKeyPem);
  const buffer = Buffer.from(raw);
  try {
    return {
      ...stored,
      privateKeyPem: "",
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: serializeWrappedSecret(wrapSecret(buffer, provider)),
      mldsaPrivateKeyWrapKeyId: "fixture-key",
    };
  } finally {
    raw.fill(0);
    buffer.fill(0);
  }
}
function update(
  options: ReturnType<typeof fixture>,
  sql: string,
  ...values: (string | number | Buffer)[]
) {
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const db = new DatabaseSync(options.path);
  try {
    db.prepare(sql).run(...values);
  } finally {
    db.close();
  }
}
function snapshot(options: ReturnType<typeof fixture>) {
  closeOpenClawStateDatabaseForTest();
  const { DatabaseSync } = requireNodeSqlite();
  const db = new DatabaseSync(options.path, { readOnly: true });
  try {
    return db.prepare("SELECT * FROM device_identities WHERE identity_key = 'primary'").get();
  } finally {
    db.close();
  }
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

it("rejects independently valid but mismatched plaintext keypairs before persistence", () => {
  const options = fixture(),
    a = plain(),
    b = plain();
  const mixed = { ...a, privateKeyPem: b.privateKeyPem, mldsaPrivateKeyPem: b.privateKeyPem };
  expect(() => validateStoredDeviceIdentity(mixed)).toThrow(/invalid persisted/);
  expect(() => insertStoredDeviceIdentityIfAbsent(mixed, options)).toThrow(/invalid persisted/);
  expect(readStoredDeviceIdentity(options)).toBeNull();
});

it("rolls back a mismatched wrapped candidate at authoritative insertion", () => {
  const options = fixture(),
    a = plain(),
    b = wrap(plain(), options.wrappingKeyProvider);
  const mixed = { ...b, deviceId: a.deviceId, publicKeyPem: a.publicKeyPem };
  expect(() => insertStoredDeviceIdentityIfAbsent(mixed, options)).toThrow(/invalid persisted/);
  expect(readStoredDeviceIdentity(options)).toBeNull();
});

it("refuses mismatched persisted wrapped keys without replacing them at runtime", () => {
  const options = fixture(),
    a = plain(),
    b = wrap(plain(), options.wrappingKeyProvider);
  insertStoredDeviceIdentityIfAbsent(wrap(a, options.wrappingKeyProvider), options);
  update(
    options,
    "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
    Buffer.from(b.mldsaPrivateKeyWrapped!),
  );
  const before = snapshot(options);
  expect(() => readStoredDeviceIdentityReadOnly(options)).toThrow(/invalid persisted/);
  expect(() => readStoredDeviceIdentity(options)).toThrow(/invalid persisted/);
  expect(() => loadOrCreateDeviceIdentity(options)).toThrow(/invalid persisted/);
  expect(snapshot(options)).toEqual(before);
});

it("Doctor rejects mismatched wrapped salvage and reports an explicit identity replacement", () => {
  const options = fixture(),
    a = plain(),
    b = wrap(plain(), options.wrappingKeyProvider);
  insertStoredDeviceIdentityIfAbsent(wrap(a, options.wrappingKeyProvider), options);
  update(
    options,
    "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
    Buffer.from(b.mldsaPrivateKeyWrapped!),
  );
  const result = repairInvalidCanonicalIdentity(options.env);
  expect(result.warnings).toEqual([]);
  expect(result.changes).toEqual(["Replaced invalid primary device identity in SQLite."]);
  expect(result.notices).toEqual([
    "The repaired device has a new identity and must be approved again.",
  ]);
  expect(readStoredDeviceIdentity(options)!.deviceId).not.toBe(a.deviceId);
});

it("Doctor preserves matching wrapped key bytes while repairing metadata", () => {
  const options = fixture(),
    a = plain();
  const original = wrap(a, options.wrappingKeyProvider);
  insertStoredDeviceIdentityIfAbsent(original, options);
  update(
    options,
    "UPDATE device_identities SET device_id = ?, created_at_ms = ? WHERE identity_key = 'primary'",
    "broken",
    -1,
  );
  const result = repairInvalidStoredDeviceIdentity(
    generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
    options,
  );
  expect(result.repaired).toBe(true);
  expect(result.rotated).toBe(false);
  expect(result.identity.deviceId).toBe(a.deviceId);
  expect(result.identity.privateKeyPem).toBe(a.privateKeyPem);
  expect(result.identity.mldsaPrivateKeyWrapped).toBe(original.mldsaPrivateKeyWrapped);
});

it.each(["intact", "invalid metadata"])(
  "Doctor does not replace an identity with the wrong wrapping key (%s)",
  (metadata) => {
    const options = fixture();
    insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
      options,
    );
    if (metadata === "invalid metadata") {
      update(
        options,
        "UPDATE device_identities SET device_id = ? WHERE identity_key = 'primary'",
        "broken",
      );
    }
    const before = snapshot(options);
    const wrongPath = path.join(path.dirname(options.wrappingKeyProvider.getKeyPath()), "wrong");
    fs.writeFileSync(wrongPath, Buffer.alloc(32, 8).toString("base64url"), { mode: 0o600 });
    const wrong = new FileKeyring(wrongPath, "fixture-key");
    providers.push(wrong);
    expect(() =>
      repairInvalidStoredDeviceIdentity(generateStoredDeviceIdentity(Date.now(), wrong), {
        ...options,
        wrappingKeyProvider: wrong,
      }),
    ).toThrow();
    expect(snapshot(options)).toEqual(before);
  },
);

it("preserves a valid concurrent winner without rotating", () => {
  const options = fixture(),
    a = plain();
  insertStoredDeviceIdentityIfAbsent(wrap(a, options.wrappingKeyProvider), options);
  const result = repairInvalidStoredDeviceIdentity(
    generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
    options,
  );
  expect(result.repaired).toBe(false);
  expect(result.rotated).toBe(false);
  expect(result.identity.privateKeyPem).toBe(a.privateKeyPem);
});

it.each(["missing", "backend failure"])(
  "Doctor preserves metadata-damaged wrapped rows when key access is %s",
  (mode) => {
    const options = fixture();
    insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
      options,
    );
    update(
      options,
      "UPDATE device_identities SET created_at_ms = ? WHERE identity_key = 'primary'",
      -1,
    );
    const before = snapshot(options);
    const provider =
      mode === "missing"
        ? undefined
        : {
            getActiveKey: () => options.wrappingKeyProvider.getActiveKey(),
            getKeyById() {
              throw new Error("fixture backend unavailable");
            },
          };
    expect(() =>
      repairInvalidStoredDeviceIdentity(
        generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
        { ...options, wrappingKeyProvider: provider },
      ),
    ).toThrow(/authenticate or decrypt/);
    expect(snapshot(options)).toEqual(before);
  },
);
