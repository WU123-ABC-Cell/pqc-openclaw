import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  serializeWrappedSecret,
  wrapSecret,
  type WrappingKeyProvider,
} from "../security/secret-wrapping.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
  upgradeDeviceIdentityPopulationWrapped,
} from "./device-identity-store.js";
import { decodeMlDsa65SecretKey } from "./mldsa65-key-storage.js";
import {
  detectLegacyDeviceIdentity,
  repairInvalidCanonicalIdentity,
} from "./state-migrations.device-identity-repair.js";
import { migrateLegacyDeviceIdentity } from "./state-migrations.device-identity.js";

const dirs: string[] = [];
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "population-upgrade-"));
  dirs.push(dir);
  const key = Buffer.alloc(32, 7);
  const wrappingKeyProvider: WrappingKeyProvider = {
    getActiveKey: () => ({ keyId: "active", key }),
    getKeyById: (id) => (id === "active" ? key : null),
  };
  const options = {
    path: path.join(dir, "state", "openclaw.sqlite"),
    env: { OPENCLAW_STATE_DIR: dir },
    wrappingKeyProvider,
  };
  const db = openOpenClawStateDatabase(options).db;
  const snapshot = () => db.prepare("SELECT * FROM device_identities ORDER BY identity_key").all();
  const add = (identityKey: string) => {
    const identity = generateStoredDeviceIdentity(1700000000000, undefined, {
      allowPlaintextPrivateKey: true,
    });
    insertStoredDeviceIdentityIfAbsent(identity, { ...options, identityKey });
    return identity;
  };
  return { options, db, snapshot, add };
}
afterEach(() => {
  closeOpenClawStateDatabaseForTest();
  for (const dir of dirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

it("upgrades custom-only plaintext and historical v1 together, preserves identity, and is idempotent", () => {
  const { options, db, add, snapshot } = fixture();
  const a = add("a");
  const b = add("b");
  const oldKey = Buffer.alloc(32, 9);
  const historical: WrappingKeyProvider = {
    getActiveKey: () => ({ keyId: "old", key: oldKey }),
    getKeyById: () => oldKey,
  };
  const raw = decodeMlDsa65SecretKey(b.privateKeyPem);
  const buffer = Buffer.from(raw);
  try {
    const wrapped = serializeWrappedSecret(wrapSecret(buffer, historical));
    db.prepare(
      "UPDATE device_identities SET private_key_pem='', mldsa_private_key_pem=NULL, mldsa_private_key_wrapped=?, mldsa_private_key_wrap_key_id='old' WHERE identity_key='b'",
    ).run(Buffer.from(wrapped));
  } finally {
    raw.fill(0);
    buffer.fill(0);
  }
  const active = options.wrappingKeyProvider;
  options.wrappingKeyProvider = {
    getActiveKey: () => active.getActiveKey(),
    getKeyById: (id) => (id === "old" ? oldKey : active.getKeyById(id)),
  };
  expect(
    detectLegacyDeviceIdentity({
      stateDir: options.env.OPENCLAW_STATE_DIR,
      env: options.env,
      doctorOnlyStateMigrations: true,
    }).hasInvalidCanonical,
  ).toBe(true);
  expect(upgradeDeviceIdentityPopulationWrapped(options)).toEqual({
    upgraded: ["a", "b"],
    createdPrimary: false,
    blocked: [],
    pendingNative: [],
  });
  for (const [identityKey, identity] of [
    ["a", a],
    ["b", b],
  ] as const) {
    expect(readStoredDeviceIdentity({ ...options, identityKey })).toMatchObject({
      deviceId: identity.deviceId,
      privateKeyPem: identity.privateKeyPem,
      createdAtMs: identity.createdAtMs,
    });
  }
  expect(readStoredDeviceIdentity(options)).toBeNull();
  const before = snapshot();
  expect(upgradeDeviceIdentityPopulationWrapped(options).upgraded).toEqual([]);
  expect(snapshot()).toEqual(before);
});

it.each(["malformed", "missing-key", "contradiction", "future"])(
  "blocks the whole batch for a later %s row",
  (mode) => {
    const { options, db, add, snapshot } = fixture();
    add("a");
    add("z");
    if (mode === "contradiction") {
      db.prepare(
        "UPDATE device_identities SET private_key_pem='conflict' WHERE identity_key='z'",
      ).run();
    } else {
      const envelope =
        mode === "malformed"
          ? "bad"
          : Buffer.from(
              JSON.stringify({
                ...(mode === "future" ? { version: 99 } : {}),
                keyId: "missing",
                iv: Buffer.alloc(12).toString("base64url"),
                ciphertext: Buffer.alloc(4032).toString("base64url"),
                authTag: Buffer.alloc(16).toString("base64url"),
              }),
            ).toString("base64url");
      db.prepare(
        "UPDATE device_identities SET private_key_pem='',mldsa_private_key_pem=NULL,mldsa_private_key_wrapped=?,mldsa_private_key_wrap_key_id='missing' WHERE identity_key='z'",
      ).run(Buffer.from(envelope));
    }
    const before = snapshot();
    const result = upgradeDeviceIdentityPopulationWrapped(options);
    expect(result.upgraded).toEqual([]);
    expect(result.blocked.map((row) => row.identityKey)).toEqual(["z"]);
    if (mode === "missing-key") {
      expect(result.blocked[0]?.reason).toBe("key-unavailable");
    }
    if (mode === "future") {
      expect(result.blocked[0]?.reason).toBe("unsupported-envelope");
    }
    expect(snapshot()).toEqual(before);
  },
);

it("routes custom-only plaintext through the real lock-held Doctor migration", async () => {
  const { options, add, snapshot } = fixture();
  add("custom");
  const detected = detectLegacyDeviceIdentity({
    stateDir: options.env.OPENCLAW_STATE_DIR,
    env: options.env,
    doctorOnlyStateMigrations: true,
  });
  const result = await migrateLegacyDeviceIdentity({
    detected,
    stateDir: options.env.OPENCLAW_STATE_DIR,
    env: options.env,
    doctorOnlyStateMigrations: true,
  });
  expect(result.warnings).toEqual([]);
  expect(result.changes).toEqual([
    'Upgraded authenticated wrapping for device identity "custom" in SQLite.',
  ]);
  expect(snapshot()).toHaveLength(1);
  expect(snapshot()[0]?.private_key_pem).toBe("");
  expect(snapshot()[0]?.mldsa_private_key_wrapped).not.toBeNull();
});

it.each(["lookup", "changed-active", "provider-failure"])(
  "preserves the population on %s provider failure",
  (mode) => {
    const { options, add, snapshot } = fixture();
    add("a");
    const before = snapshot();
    const original = options.wrappingKeyProvider;
    let calls = 0;
    options.wrappingKeyProvider = {
      getActiveKey: () => {
        if (++calls === 2) {
          if (mode === "provider-failure") {
            throw new Error("injected provider failure");
          }
          if (mode === "changed-active") {
            return { keyId: "other", key: Buffer.alloc(32, 8) };
          }
        }
        return original.getActiveKey();
      },
      getKeyById: (id) => (mode === "lookup" ? Buffer.alloc(32, 8) : original.getKeyById(id)),
    };
    expect(() => upgradeDeviceIdentityPopulationWrapped(options)).toThrow();
    expect(snapshot()).toEqual(before);
  },
);

it("keeps an authenticated v2 historical row byte-for-byte while upgrading its sibling", () => {
  const { options, add, snapshot } = fixture();
  add("a");
  const oldKey = Buffer.alloc(32, 9);
  const old: WrappingKeyProvider = {
    getActiveKey: () => ({ keyId: "old", key: oldKey }),
    getKeyById: () => oldKey,
  };
  insertStoredDeviceIdentityIfAbsent(
    generateStoredDeviceIdentity(1700000000000, old, { identityKey: "z" }),
    { ...options, identityKey: "z", wrappingKeyProvider: old },
  );
  const active = options.wrappingKeyProvider;
  options.wrappingKeyProvider = {
    getActiveKey: () => active.getActiveKey(),
    getKeyById: (id) => (id === "old" ? oldKey : active.getKeyById(id)),
  };
  const before = snapshot()[1];
  expect(upgradeDeviceIdentityPopulationWrapped(options).upgraded).toEqual(["a"]);
  expect(snapshot()[1]).toEqual(before);
});

it("rolls back an earlier update when a later SQLite write fails", () => {
  const { options, db, add, snapshot } = fixture();
  add("a");
  add("z");
  db.exec(
    "CREATE TRIGGER reject_z BEFORE UPDATE ON device_identities WHEN NEW.identity_key='z' BEGIN SELECT RAISE(ABORT,'injected write failure'); END",
  );
  const before = snapshot();
  expect(() => upgradeDeviceIdentityPopulationWrapped(options)).toThrow(/injected write failure/);
  expect(snapshot()).toEqual(before);
});

it("rejects a population change between planning and commit", () => {
  const { options, db, add, snapshot } = fixture();
  add("a");
  const original = options.wrappingKeyProvider;
  let calls = 0;
  options.wrappingKeyProvider = {
    getActiveKey: () => {
      if (++calls === 2) {
        db.prepare("UPDATE device_identities SET updated_at_ms=updated_at_ms+1").run();
      }
      return original.getActiveKey();
    },
    getKeyById: (id) => original.getKeyById(id),
  };
  expect(() => upgradeDeviceIdentityPopulationWrapped(options)).toThrow(/population changed/);
  expect(snapshot()[0]?.mldsa_private_key_wrapped).toBeNull();
});

it("preserves Apple rows without claiming native verification", () => {
  const { options, db, add, snapshot } = fixture();
  add("a");
  const pub = Buffer.alloc(1952, 3);
  db.prepare(
    "INSERT INTO device_identities(identity_key,device_id,public_key_pem,private_key_pem,created_at_ms,updated_at_ms) VALUES(?,?,?,?,1,1)",
  ).run(
    "apple-mldsa65-primary",
    createHash("sha256").update(pub).digest("hex"),
    `MLDSA65-PUBLIC-KEY:${pub.toString("base64")}`,
    `MLDSA65-SEED:${Buffer.alloc(32, 4).toString("base64")}`,
  );
  const before = snapshot()[1];
  expect(upgradeDeviceIdentityPopulationWrapped(options)).toEqual({
    upgraded: ["a"],
    createdPrimary: false,
    blocked: [],
    pendingNative: ["apple-mldsa65-primary"],
  });
  expect(snapshot()[1]).toEqual(before);
});

it("Doctor preserves a malformed primary rather than replacing its identity", () => {
  const { options, db, add, snapshot } = fixture();
  add("primary");
  db.prepare("UPDATE device_identities SET device_id='damaged'").run();
  const before = snapshot();
  const result = repairInvalidCanonicalIdentity(options.env);
  expect(result.changes).toEqual([]);
  expect(result.warnings).toHaveLength(1);
  expect(result.notices).toBeUndefined();
  expect(snapshot()).toEqual(before);
});
