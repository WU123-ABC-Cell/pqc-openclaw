import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { FileKeyring, resetDefaultKeyringCache } from "../security/keyring-provider.js";
import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  wrapSecret,
} from "../security/secret-wrapping.js";
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
import {
  detectLegacyDeviceIdentity,
  repairInvalidCanonicalIdentity,
} from "./state-migrations.device-identity-repair.js";
import { migrateLegacyDeviceIdentity } from "./state-migrations.device-identity.js";

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
function wrap(stored: StoredDeviceIdentity, provider: FileKeyring, legacy = false) {
  const raw = decodeMlDsa65SecretKey(stored.privateKeyPem);
  const buffer = Buffer.from(raw);
  try {
    return {
      ...stored,
      privateKeyPem: "",
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: serializeWrappedSecret(
        wrapSecret(
          buffer,
          provider,
          legacy
            ? undefined
            : Buffer.from(
                JSON.stringify([
                  "device_identities",
                  "primary",
                  stored.deviceId,
                  stored.publicKeyPem,
                ]),
              ),
        ),
      ),
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

it("Doctor upgrades an old envelope without a legacy identity file and preserves the signing identity", () => {
  const options = fixture();
  const identity = plain();
  insertStoredDeviceIdentityIfAbsent(wrap(identity, options.wrappingKeyProvider), options);
  const legacy = wrap(identity, options.wrappingKeyProvider, true);
  update(
    options,
    "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
    Buffer.from(legacy.mldsaPrivateKeyWrapped),
  );
  const before = snapshot(options);
  expect(() => readStoredDeviceIdentityReadOnly(options)).toThrow(/doctor --fix/);
  expect(snapshot(options)).toEqual(before);
  const detection = () =>
    detectLegacyDeviceIdentity({
      stateDir: options.env.OPENCLAW_STATE_DIR,
      env: options.env,
      doctorOnlyStateMigrations: true,
    });
  expect(detection().hasInvalidCanonical).toBe(true);
  const result = repairInvalidCanonicalIdentity(options.env);
  expect(result.warnings).toEqual([]);
  expect(result.notices).toBeUndefined();
  const upgraded = readStoredDeviceIdentity(options)!;
  expect(upgraded.deviceId).toBe(identity.deviceId);
  expect(upgraded.privateKeyPem).toBe(identity.privateKeyPem);
  expect(deserializeWrappedSecret(upgraded.mldsaPrivateKeyWrapped!).version).toBe(2);
  expect(detection().hasInvalidCanonical).toBe(false);
  const after = snapshot(options);
  expect(repairInvalidCanonicalIdentity(options.env).changes).toEqual([]);
  expect(snapshot(options)).toEqual(after);
});

it("Doctor upgrades custom legacy rows without creating a missing primary identity", async () => {
  const options = fixture();
  const customOptions = { ...options, identityKey: "custom" };
  const identity = loadOrCreateDeviceIdentity(customOptions);
  const stored = readStoredDeviceIdentity(customOptions)!;
  const legacy = wrap(stored, options.wrappingKeyProvider, true);
  update(
    options,
    "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'custom'",
    Buffer.from(legacy.mldsaPrivateKeyWrapped),
  );
  expect(
    detectLegacyDeviceIdentity({
      stateDir: options.env.OPENCLAW_STATE_DIR,
      env: options.env,
      doctorOnlyStateMigrations: true,
    }).hasInvalidCanonical,
  ).toBe(true);
  const stateDir = options.env.OPENCLAW_STATE_DIR;
  const detected = detectLegacyDeviceIdentity({
    stateDir,
    env: options.env,
    doctorOnlyStateMigrations: true,
  });
  const before = snapshot(options);
  expect(await migrateLegacyDeviceIdentity({ stateDir, env: options.env, detected })).toEqual({
    changes: [],
    warnings: [],
  });
  expect(snapshot(options)).toEqual(before);
  const result = await migrateLegacyDeviceIdentity({
    stateDir,
    env: options.env,
    detected,
    doctorOnlyStateMigrations: true,
  });
  expect(result.warnings).toEqual([]);
  expect(result.changes).toEqual([
    'Upgraded authenticated wrapping for device identity "custom" in SQLite.',
  ]);
  expect(readStoredDeviceIdentity(customOptions)?.privateKeyPem).toBe(identity.privateKeyPem);
  expect(readStoredDeviceIdentity(options)).toBeNull();
  expect(repairInvalidCanonicalIdentity(options.env).changes).toEqual([]);
});

it("Doctor preserves an old wrapped row when its original key is unavailable", () => {
  const options = fixture();
  const stored = insertStoredDeviceIdentityIfAbsent(
    generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
    options,
  );
  const legacy = wrap(stored, options.wrappingKeyProvider, true);
  update(
    options,
    "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
    Buffer.from(legacy.mldsaPrivateKeyWrapped),
  );
  const before = snapshot(options);
  const wrongPath = path.join(options.env.OPENCLAW_STATE_DIR, "wrong-upgrade-key");
  fs.writeFileSync(wrongPath, Buffer.alloc(32, 8).toString("base64url"), { mode: 0o600 });
  const result = repairInvalidCanonicalIdentity({
    ...options.env,
    OPENCLAW_WRAP_KEY_FILE: wrongPath,
  });
  expect(result.changes).toEqual([]);
  expect(result.warnings).toHaveLength(1);
  expect(snapshot(options)).toEqual(before);
});

it.each(["device_id", "mldsa_public_key_pem"])(
  "Doctor preserves a bound row when %s authentication fails",
  (column) => {
    const options = fixture();
    insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
      options,
    );
    const replacement = column === "device_id" ? "0".repeat(64) : plain().publicKeyPem;
    update(
      options,
      `UPDATE device_identities SET ${column} = ? WHERE identity_key = 'primary'`,
      replacement,
    );
    const before = snapshot(options);
    expect(() => readStoredDeviceIdentity(options)).toThrow(/Cannot authenticate or decrypt/);
    const result = repairInvalidCanonicalIdentity(options.env);
    expect(result.changes).toEqual([]);
    expect(result.warnings).toHaveLength(1);
    expect(snapshot(options)).toEqual(before);
  },
);

it.each([undefined, 1, 3])(
  "Doctor preserves a bound envelope after a version change to %s",
  (version) => {
    const options = fixture();
    const stored = insertStoredDeviceIdentityIfAbsent(
      generateStoredDeviceIdentity(Date.now(), options.wrappingKeyProvider),
      options,
    );
    const envelope = deserializeWrappedSecret(stored.mldsaPrivateKeyWrapped!);
    update(
      options,
      "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
      Buffer.from(Buffer.from(JSON.stringify({ ...envelope, version })).toString("base64url")),
    );
    const before = snapshot(options);
    const result = repairInvalidCanonicalIdentity(options.env);
    expect(result.changes).toEqual([]);
    expect(result.warnings).toHaveLength(1);
    expect(snapshot(options)).toEqual(before);
  },
);

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
  expect(() => insertStoredDeviceIdentityIfAbsent(mixed, options)).toThrow(
    /Cannot authenticate or decrypt/,
  );
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
  expect(() => readStoredDeviceIdentityReadOnly(options)).toThrow(/Cannot authenticate or decrypt/);
  expect(() => readStoredDeviceIdentity(options)).toThrow(/Cannot authenticate or decrypt/);
  expect(() => loadOrCreateDeviceIdentity(options)).toThrow(/Cannot authenticate or decrypt/);
  expect(snapshot(options)).toEqual(before);
});

it("Doctor blocks mismatched wrapped salvage without replacing the identity", () => {
  const options = fixture(),
    a = plain(),
    b = wrap({ ...a, privateKeyPem: plain().privateKeyPem }, options.wrappingKeyProvider);
  insertStoredDeviceIdentityIfAbsent(wrap(a, options.wrappingKeyProvider), options);
  update(
    options,
    "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
    Buffer.from(b.mldsaPrivateKeyWrapped!),
  );
  const before = snapshot(options);
  const result = repairInvalidCanonicalIdentity(options.env);
  expect(result.warnings).toHaveLength(1);
  expect(result.changes).toEqual([]);
  expect(result.notices).toBeUndefined();
  expect(snapshot(options)).toEqual(before);
});

it("Doctor upgrades legacy wrapping while preserving matching identity keys and repairing metadata", () => {
  const options = fixture(),
    a = plain();
  insertStoredDeviceIdentityIfAbsent(wrap(a, options.wrappingKeyProvider), options);
  const original = wrap(a, options.wrappingKeyProvider, true);
  update(
    options,
    "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
    Buffer.from(original.mldsaPrivateKeyWrapped),
  );
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
  expect(deserializeWrappedSecret(result.identity.mldsaPrivateKeyWrapped!).version).toBe(2);
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
