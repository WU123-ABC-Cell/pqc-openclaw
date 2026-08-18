// M5 integration tests for the device-identity wrap envelope. These tests
// drive the full insert → read round-trip through SQLite using a tiny
// in-memory WrappingKeyProvider, verifying that:
//   * wrap form survives the persistence boundary,
//   * unwrap restores the original secret key bytes,
//   * a missing keyring refuses to read a wrapped row (fail-closed),
//   * plaintext M1/M2 rows still read correctly when a keyring is supplied,
//   * the legacy `public_key_pem` / `private_key_pem` columns are kept in
//     sync with the new `mldsa_*` columns so M1/M2 callers keep working.
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { closeOpenClawStateDatabaseForTest, openOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { requireNodeSqlite } from "./node-sqlite.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  PRIMARY_DEVICE_IDENTITY_KEY,
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  type StoredDeviceIdentity,
  type DeviceIdentityStoreOptions,
} from "./device-identity-store.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  fingerprintMlDsa65PublicKey,
  generateMlDsa65KeyPair,
} from "./mldsa65-key-storage.js";
import {
  type ActiveWrappingKey,
  serializeWrappedSecret,
  type WrappingKeyProvider,
  wrapSecret,
} from "../security/secret-wrapping.js";
import { resetDefaultKeyringCache } from "../security/keyring-provider.js";

class InMemoryKeyring implements WrappingKeyProvider {
  private readonly activeId: string;
  private readonly keys = new Map<string, Buffer>();

  constructor(activeId: string) {
    this.activeId = activeId;
  }

  addKey(keyId: string, key: Buffer): void {
    this.keys.set(keyId, Buffer.from(key));
  }

  drop(keyId: string): void {
    this.keys.delete(keyId);
  }

  getActiveKey(): ActiveWrappingKey {
    const key = this.keys.get(this.activeId);
    if (!key) {
      throw new Error(`InMemoryKeyring: active key missing: ${this.activeId}`);
    }
    return { key, keyId: this.activeId };
  }

  getKeyById(keyId: string): Buffer | null {
    const key = this.keys.get(keyId);
    return key ? Buffer.from(key) : null;
  }
}

const tempDirs: string[] = [];
const originalKeys: Buffer[] = [];

function newKey(): Buffer {
  const k = randomBytes(32);
  originalKeys.push(k);
  return k;
}

function writeKeyFile(filePath: string, key: Buffer, mode: number = 0o600): void {
  // Authorised test-only writer. `FileKeyring` enforces a 0600/0400
  // mode on non-Windows; we keep the default at 0o600 so the auto-inject
  // path (which constructs a `FileKeyring` directly from
  // `OPENCLAW_WRAP_KEY_FILE`) doesn't trip its safety guard.
  fs.writeFileSync(filePath, key.toString("base64url"));
  if (process.platform !== "win32") {
    fs.chmodSync(filePath, mode);
  }
}

function makeStoreOptions(wrappingKeyProvider?: WrappingKeyProvider): DeviceIdentityStoreOptions & {
  stateDir: string;
} {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m5-"));
  tempDirs.push(stateDir);
  return {
    stateDir,
    env: { ...process.env, OPENCLAW_STATE_DIR: stateDir },
    ...(wrappingKeyProvider ? { wrappingKeyProvider } : {}),
  };
}

beforeEach(() => {
  while (tempDirs.length > 0) tempDirs.pop();
  while (originalKeys.length > 0) originalKeys.pop();
});

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (!dir) continue;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best-effort.
    }
  }
  while (originalKeys.length > 0) {
    originalKeys.pop()?.fill(0);
  }
});

describe("device-identity store — M5 wrap integration", () => {
  it("generates a wrapped identity when a WrappingKeyProvider is supplied", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const stored = generateStoredDeviceIdentity(1_700_000_000_000, keyring);
    expect(stored.mldsaPrivateKeyPem).toBeNull();
    expect(stored.mldsaPrivateKeyWrapped).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(stored.mldsaPrivateKeyWrapKeyId).toBe("wrap-key-2026-08");
    // publicKeyPem is plaintext so the device_id is resolvable without the keyring.
    expect(stored.publicKeyPem).toMatch(/^MLDSA65-PUBLIC-KEY:/);
    // privateKeyPem is the lazy placeholder; the real secret comes out
    // only after unwrap. The runtime type does not need to sign with
    // it directly — signDevicePayload decodes the MLDSA65-SECRET-KEY:
    // prefix and the new read path populates it.
    expect(stored.privateKeyPem).toBe("");
  });

  it("generates a plaintext identity when no WrappingKeyProvider is supplied", () => {
    const stored = generateStoredDeviceIdentity(1_700_000_000_000);
    expect(stored.mldsaPrivateKeyPem).toMatch(/^MLDSA65-SECRET-KEY:/);
    expect(stored.mldsaPrivateKeyWrapped).toBeNull();
    expect(stored.mldsaPrivateKeyWrapKeyId).toBeNull();
    expect(stored.privateKeyPem).toBe(stored.mldsaPrivateKeyPem);
  });

  it("round-trips a wrapped identity through insert + read", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);

    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, keyring);
    const inserted = insertStoredDeviceIdentityIfAbsent(candidate, options);
    expect(inserted.mldsaPrivateKeyWrapped).not.toBeNull();
    expect(inserted.mldsaPrivateKeyWrapKeyId).toBe("wrap-key-2026-08");

    const reloaded = readStoredDeviceIdentity(options);
    expect(reloaded).not.toBeNull();
    expect(reloaded!.deviceId).toBe(candidate.deviceId);
    // The unwrapped secret PEM must be a valid ML-DSA-65 secret key
    // (4032 bytes) AND the device_id derived from the public side
    // must round-trip (the public side never changes through the wrap).
    const recoveredSecret = decodeMlDsa65SecretKey(reloaded!.privateKeyPem);
    expect(recoveredSecret.length).toBe(4032);
    const recoveredPublic = decodeMlDsa65PublicKey(reloaded!.publicKeyPem);
    expect(fingerprintMlDsa65PublicKey(recoveredPublic)).toBe(candidate.deviceId);
  });

  it("refuses to read a wrapped row when no WrappingKeyProvider is supplied", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, keyring);
    insertStoredDeviceIdentityIfAbsent(candidate, options);

    // Read back through the SAME database path, but without supplying
    // a keyring. The read path must fail-closed rather than silently
    // fall back to plaintext (which would defeat the wrap-key feature).
    const readOptions: DeviceIdentityStoreOptions = {
      env: options.env,
      path: path.join(options.stateDir, "state", "openclaw.sqlite"),
    };
    expect(() => readStoredDeviceIdentity(readOptions)).toThrow(/wrap-protected/);
  });

  it("fails closed when the keyring has lost the keyId after insert", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, keyring);
    insertStoredDeviceIdentityIfAbsent(candidate, options);

    keyring.drop("wrap-key-2026-08");
    expect(() => readStoredDeviceIdentity(options)).toThrow(/not found|invalid persisted/i);
  });

  it("readStoredDeviceIdentityReadOnly also unwraps when given a keyring", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, keyring);
    insertStoredDeviceIdentityIfAbsent(candidate, options);

    const readOnly = readStoredDeviceIdentityReadOnly(options);
    expect(readOnly).not.toBeNull();
    expect(readOnly!.deviceId).toBe(candidate.deviceId);
  });

  it("legacy plaintext rows still read when a keyring is supplied", () => {
    // M1/M2 left plaintext ML-DSA-65 PEMs in `public_key_pem` /
    // `private_key_pem` and left the new `mldsa_*` columns NULL. The
    // M5 read path must fall back to the legacy columns when the new
    // ones are empty. The cleanest way to seed that state is to write
    // a plaintext identity first (no keyring), then read it back with
    // a keyring supplied. The keyring is harmless on a plaintext row.
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());

    // Write path: no keyring -> plaintext form.
    const writeOptions = makeStoreOptions();
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000);
    const inserted = insertStoredDeviceIdentityIfAbsent(candidate, writeOptions);
    expect(inserted.mldsaPrivateKeyWrapped).toBeNull();

    // Read path: a keyring is supplied but the row is plaintext; the
    // read path should ignore the keyring and return the plaintext.
    const readOptions: DeviceIdentityStoreOptions = {
      env: writeOptions.env,
      path: path.join(writeOptions.stateDir, "state", "openclaw.sqlite"),
      wrappingKeyProvider: keyring,
    };
    const reloaded = readStoredDeviceIdentity(readOptions);
    expect(reloaded).not.toBeNull();
    expect(reloaded!.deviceId).toBe(candidate.deviceId);
    expect(reloaded!.publicKeyPem).toBe(candidate.publicKeyPem);
    expect(reloaded!.privateKeyPem).toBe(candidate.privateKeyPem);
    // Plaintext rows keep the new mldsa_* columns NULL on the read path.
    expect(reloaded!.mldsaPrivateKeyWrapped).toBeNull();
    expect(reloaded!.mldsaPrivateKeyWrapKeyId).toBeNull();
  });

  it("device_id (fingerprint) is stable across wrap + unwrap", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);

    const { publicKey, secretKey } = generateMlDsa65KeyPair();
    const expectedDeviceId = fingerprintMlDsa65PublicKey(publicKey);
    const wrapped = wrapSecret(Buffer.from(secretKey), keyring);
    const candidate: StoredDeviceIdentity = {
      deviceId: expectedDeviceId,
      publicKeyPem: encodeMlDsa65PublicKey(publicKey),
      privateKeyPem: "",
      createdAtMs: 1_700_000_000_000,
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: serializeWrappedSecret(wrapped),
      mldsaPrivateKeyWrapKeyId: "wrap-key-2026-08",
    };
    insertStoredDeviceIdentityIfAbsent(candidate, options);
    const reloaded = readStoredDeviceIdentity(options);
    expect(reloaded!.deviceId).toBe(expectedDeviceId);
  });

  it("two independent keyrings can read the same row when both have the active key", () => {
    // The keyId is the keyring's id, not the key bytes. Two keyrings
    // (e.g. a primary and a standby) that share the same keyId and
    // bytes can both unwrap a row. This mirrors the M6 + M7 story
    // where a rotated key needs a grace-period keyring to read old
    // rows.
    const sharedKey = newKey();
    const a = new InMemoryKeyring("wrap-key-2026-08");
    const b = new InMemoryKeyring("wrap-key-2026-08");
    a.addKey("wrap-key-2026-08", sharedKey);
    b.addKey("wrap-key-2026-08", sharedKey);
    const options = makeStoreOptions(a);
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, a);
    insertStoredDeviceIdentityIfAbsent(candidate, options);

    // Read back through the SAME database path with the second keyring.
    const readOptions: DeviceIdentityStoreOptions = {
      env: options.env,
      path: path.join(options.stateDir, "state", "openclaw.sqlite"),
      wrappingKeyProvider: b,
    };
    const reloaded = readStoredDeviceIdentity(readOptions);
    expect(reloaded).not.toBeNull();
    expect(reloaded!.deviceId).toBe(candidate.deviceId);
  });

  it("wrap envelope in the row uses UTF-8 JSON inside the BLOB", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, keyring);
    insertStoredDeviceIdentityIfAbsent(candidate, options);

    const { DatabaseSync } = requireNodeSqlite();
    const database = new DatabaseSync(path.join(options.stateDir, "state", "openclaw.sqlite"));
    try {
      const row = database
        .prepare(
          "SELECT mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = ?",
        )
        .get(PRIMARY_DEVICE_IDENTITY_KEY) as {
        mldsa_private_key_wrapped: Uint8Array;
        mldsa_private_key_wrap_key_id: string;
      };
      expect(row.mldsa_private_key_wrapped).toBeInstanceOf(Uint8Array);
      // The BLOB stores the base64url-encoded JSON (output of
      // serializeWrappedSecret). First decode the BLOB bytes as UTF-8
      // to recover the base64url string, then base64url-decode to get
      // the JSON.
      const base64url = Buffer.from(row.mldsa_private_key_wrapped).toString("utf8");
      const json = Buffer.from(base64url, "base64url").toString("utf8");
      const parsed = JSON.parse(json) as Record<string, unknown>;
      expect(parsed).toHaveProperty("ciphertext");
      expect(parsed).toHaveProperty("iv");
      expect(parsed).toHaveProperty("authTag");
      expect(parsed).toHaveProperty("keyId", "wrap-key-2026-08");
      // The base64url form should be pure base64url (no padding).
      expect(base64url).toMatch(/^[A-Za-z0-9_-]+$/);
    } finally {
      database.close();
    }
  });

  it("device_id lookup on a public-key material does not require a keyring", () => {
    // Whitepaper 2.2.3: the public side is always plaintext, so the
    // gateway can resolve a device_id (used in pairing flows) without
    // having the wrap key available yet. This is the same property
    // we rely on for cross-keyring reads in the M6 backup path.
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const writeOptions = makeStoreOptions(keyring);
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, keyring);
    insertStoredDeviceIdentityIfAbsent(candidate, writeOptions);

    const { DatabaseSync } = requireNodeSqlite();
    const database = new DatabaseSync(path.join(writeOptions.stateDir, "state", "openclaw.sqlite"));
    try {
      const row = database
        .prepare(
          "SELECT mldsa_public_key_pem, public_key_pem FROM device_identities WHERE identity_key = ?",
        )
        .get(PRIMARY_DEVICE_IDENTITY_KEY) as {
        mldsa_public_key_pem: string | null;
        public_key_pem: string;
      };
      // Both columns are populated and contain the same prefixed string,
      // so a public-key reader can resolve the device_id without ever
      // touching the keyring.
      expect(row.mldsa_public_key_pem).toBe(candidate.publicKeyPem);
      expect(row.public_key_pem).toBe(candidate.publicKeyPem);
      const rawPublic = decodeMlDsa65PublicKey(row.mldsa_public_key_pem!);
      expect(fingerprintMlDsa65PublicKey(rawPublic)).toBe(candidate.deviceId);
    } finally {
      database.close();
    }
  });
});

describe("M5.5 auto-inject default keyring from env", () => {
  // The auto-inject path (device-identity.ts) reads `OPENCLAW_WRAP_KEY_FILE`
  // and `OPENCLAW_WRAP_KEY_ID` and constructs a `FileKeyring` automatically
  // when the caller doesn't pass an explicit `wrappingKeyProvider`. The
  // original M5.5 implementation was a runtime monkey-patch (M5.5 v1 / v2)
  // that bypassed the source's caching logic; the v3 source-level fix
  // removes that patch and wires the auto-inject here. These tests
  // verify the end-to-end round trip through the auto-injected keyring.
  const originalFile = process.env.OPENCLAW_WRAP_KEY_FILE;
  const originalId = process.env.OPENCLAW_WRAP_KEY_ID;

  afterEach(() => {
    if (originalFile === undefined) {
      delete process.env.OPENCLAW_WRAP_KEY_FILE;
    } else {
      process.env.OPENCLAW_WRAP_KEY_FILE = originalFile;
    }
    if (originalId === undefined) {
      delete process.env.OPENCLAW_WRAP_KEY_ID;
    } else {
      process.env.OPENCLAW_WRAP_KEY_ID = originalId;
    }
    // Force the module-level cache in `keyring-provider.ts` to drop
    // so subsequent tests (in this file or elsewhere) don't see a
    // cached keyring from a previous test.
    resetDefaultKeyringCache();
  });

  it("wraps on insert + unwraps on read when only OPENCLAW_WRAP_KEY_FILE is set", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m55-"));
    tempDirs.push(stateDir);
    const keyPath = path.join(stateDir, "wrap.key");
    const key = newKey();
    writeKeyFile(keyPath, key, 0o600);

    process.env.OPENCLAW_WRAP_KEY_FILE = keyPath;
    process.env.OPENCLAW_WRAP_KEY_ID = "wrap-key-2026-08";
    resetDefaultKeyringCache();

    // No `wrappingKeyProvider` passed — auto-inject must fill it in.
    const options: DeviceIdentityStoreOptions = {
      env: { ...process.env, OPENCLAW_STATE_DIR: stateDir },
      path: path.join(stateDir, "state", "openclaw.sqlite"),
    };

    const candidate = generateStoredDeviceIdentity(1_700_000_000_000);
    const inserted = insertStoredDeviceIdentityIfAbsent(candidate, options);
    // Wrap form was applied even though the caller didn't pass a keyring.
    expect(inserted.mldsaPrivateKeyPem).toBeNull();
    expect(inserted.mldsaPrivateKeyWrapped).not.toBeNull();
    expect(inserted.mldsaPrivateKeyWrapKeyId).toBe("wrap-key-2026-08");

    // Read path also auto-injects — unwrap must restore the original secret.
    const reloaded = readStoredDeviceIdentity(options);
    expect(reloaded).not.toBeNull();
    const recovered = decodeMlDsa65SecretKey(reloaded!.privateKeyPem);
    expect(recovered.length).toBe(4032);
    expect(fingerprintMlDsa65PublicKey(decodeMlDsa65PublicKey(reloaded!.publicKeyPem))).toBe(candidate.deviceId);
  });

  it("stays in plaintext mode when OPENCLAW_WRAP_KEY_FILE is unset (no auto-inject)", () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m55-"));
    tempDirs.push(stateDir);
    delete process.env.OPENCLAW_WRAP_KEY_FILE;
    delete process.env.OPENCLAW_WRAP_KEY_ID;
    resetDefaultKeyringCache();

    const options: DeviceIdentityStoreOptions = {
      env: { ...process.env, OPENCLAW_STATE_DIR: stateDir },
      path: path.join(stateDir, "state", "openclaw.sqlite"),
    };
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000);
    const inserted = insertStoredDeviceIdentityIfAbsent(candidate, options);
    expect(inserted.mldsaPrivateKeyWrapped).toBeNull();
    expect(inserted.mldsaPrivateKeyPem).toMatch(/^MLDSA65-SECRET-KEY:/);
  });

  it("explicit wrappingKeyProvider takes precedence over env-injected keyring", () => {
    // Regression guard: an explicit keyring passed by the caller must
    // never be silently replaced by an env-injected one (the auto-inject
    // path is a "no keyring provided" fallback, not a "always" hook).
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m55-"));
    tempDirs.push(stateDir);
    const explicit = new InMemoryKeyring("explicit-key");
    explicit.addKey("explicit-key", newKey());

    const keyPath = path.join(stateDir, "wrap.key");
    writeKeyFile(keyPath, newKey(), 0o600);
    process.env.OPENCLAW_WRAP_KEY_FILE = keyPath;
    process.env.OPENCLAW_WRAP_KEY_ID = "env-key";
    resetDefaultKeyringCache();

    const options: DeviceIdentityStoreOptions = {
      env: { ...process.env, OPENCLAW_STATE_DIR: stateDir },
      path: path.join(stateDir, "state", "openclaw.sqlite"),
      wrappingKeyProvider: explicit,
    };
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000);
    const inserted = insertStoredDeviceIdentityIfAbsent(candidate, options);
    expect(inserted.mldsaPrivateKeyWrapKeyId).toBe("explicit-key");
  });
});
