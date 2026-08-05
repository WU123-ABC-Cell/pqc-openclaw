// PQC step 2.3.5.C: integration tests for state-migration wrap-key rotation.
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  unwrapSecret,
  wrapSecret,
  type ActiveWrappingKey,
  type WrappingKeyProvider,
} from "../security/secret-wrapping.js";
import { rotateDeviceIdentityWrappingKey } from "./state-migrations.rotate-wrapping-key.js";

const KEY_BYTES = 32;

function makeProvider(
  keyId: string,
  key: Buffer,
  allKeys: Map<string, Buffer>,
): WrappingKeyProvider {
  return {
    getActiveKey: (): ActiveWrappingKey => ({ key, keyId }),
    getKeyById: (id: string) => allKeys.get(id) ?? null,
  };
}

function insertDeviceIdentityRow(
  env: NodeJS.ProcessEnv,
  params: {
    identity_key: string;
    device_id: string;
    public_key_pem: string;
    private_key_pem: string;
    mldsa_private_key_pem?: string | null;
    private_key_wrapped?: string | null;
    private_key_wrap_key_id?: string | null;
    mldsa_private_key_wrapped?: string | null;
    mldsa_private_key_wrap_key_id?: string | null;
    created_at_ms: number;
    updated_at_ms: number;
  },
): void {
  const database = openOpenClawStateDatabase({ env });
  database.db
    .prepare(
      `INSERT INTO device_identities (
        identity_key, device_id, public_key_pem, private_key_pem,
        mldsa_public_key_pem, mldsa_private_key_pem,
        private_key_wrapped, private_key_wrap_key_id,
        mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id,
        created_at_ms, updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      params.identity_key,
      params.device_id,
      params.public_key_pem,
      params.private_key_pem,
      null,
      params.mldsa_private_key_pem ?? null,
      params.private_key_wrapped ?? null,
      params.private_key_wrap_key_id ?? null,
      params.mldsa_private_key_wrapped ?? null,
      params.mldsa_private_key_wrap_key_id ?? null,
      params.created_at_ms,
      params.updated_at_ms,
    );
}

describe("rotateDeviceIdentityWrappingKey", () => {
  const tempDirs = useAutoCleanupTempDirTracker((cleanup) => {
    afterEach(() => {
      closeOpenClawStateDatabaseForTest();
      cleanup();
    });
  });

  function useStateDir(): { env: NodeJS.ProcessEnv; stateDir: string } {
    const stateDir = tempDirs.make("openclaw-rotate-wrapping-key-");
    return {
      env: { ...process.env, HOME: stateDir, OPENCLAW_STATE_DIR: stateDir },
    };
  }

  it("rotates Ed25519 + ML-DSA wrap from old key to new key", () => {
    const { env } = useStateDir();
    const oldKey = randomBytes(KEY_BYTES);
    const newKey = randomBytes(KEY_BYTES);
    const allKeys = new Map([
      ["old-key-id", oldKey],
      ["new-key-id", newKey],
    ]);
    const oldProvider = makeProvider("old-key-id", oldKey, allKeys);
    const newProvider = makeProvider("new-key-id", newKey, allKeys);
    const ed25519Plain = Buffer.from("ed25519-private-key");
    const mldsaPlain = Buffer.from("mldsa-private-key");

    insertDeviceIdentityRow(env, {
      identity_key: "primary",
      device_id: "dev-1",
      public_key_pem: "public-key",
      private_key_pem: ed25519Plain.toString("utf8"),
      mldsa_private_key_pem: mldsaPlain.toString("utf8"),
      private_key_wrapped: serializeWrappedSecret(wrapSecret(ed25519Plain, oldProvider)),
      private_key_wrap_key_id: "old-key-id",
      mldsa_private_key_wrapped: serializeWrappedSecret(wrapSecret(mldsaPlain, oldProvider)),
      mldsa_private_key_wrap_key_id: "old-key-id",
      created_at_ms: 1000,
      updated_at_ms: 1000,
    });

    const result = rotateDeviceIdentityWrappingKey({
      env,
      newProvider,
      newKeyId: "new-key-id",
      oldProvider,
    });

    expect(result.rotatedRows).toBe(1);
    expect(result.toKeyId).toBe("new-key-id");
    expect(result.fromKeyIds.has("old-key-id")).toBe(true);

    const database = openOpenClawStateDatabase({ env });
    const row = database.db
      .prepare("SELECT * FROM device_identities WHERE identity_key = 'primary'")
      .get() as {
        private_key_wrapped: string;
        private_key_wrap_key_id: string;
        mldsa_private_key_wrapped: string;
        mldsa_private_key_wrap_key_id: string;
        updated_at_ms: number;
      };
    expect(row.private_key_wrap_key_id).toBe("new-key-id");
    expect(row.mldsa_private_key_wrap_key_id).toBe("new-key-id");
    expect(row.updated_at_ms).toBeGreaterThan(1000);

    const ed = unwrapSecret(deserializeWrappedSecret(row.private_key_wrapped), newProvider);
    expect(ed.toString("utf8")).toBe("ed25519-private-key");
    const ml = unwrapSecret(deserializeWrappedSecret(row.mldsa_private_key_wrapped), newProvider);
    expect(ml.toString("utf8")).toBe("mldsa-private-key");
  });

  it("skips rows that already use the new key", () => {
    const { env } = useStateDir();
    const newKey = randomBytes(KEY_BYTES);
    const allKeys = new Map([["new-key-id", newKey]]);
    const newProvider = makeProvider("new-key-id", newKey, allKeys);

    insertDeviceIdentityRow(env, {
      identity_key: "primary",
      device_id: "dev-1",
      public_key_pem: "public-key",
      private_key_pem: "plaintext-priv",
      private_key_wrapped: serializeWrappedSecret(wrapSecret(Buffer.from("secret"), newProvider)),
      private_key_wrap_key_id: "new-key-id",
      created_at_ms: 1000,
      updated_at_ms: 1000,
    });

    const result = rotateDeviceIdentityWrappingKey({
      env,
      newProvider,
      newKeyId: "new-key-id",
    });

    expect(result.rotatedRows).toBe(0);
    expect(result.fromKeyIds.size).toBe(0);
  });

  it("skips legacy plaintext rows (no wrap columns)", () => {
    const { env } = useStateDir();
    const newKey = randomBytes(KEY_BYTES);
    const allKeys = new Map([["new-key-id", newKey]]);
    const newProvider = makeProvider("new-key-id", newKey, allKeys);

    insertDeviceIdentityRow(env, {
      identity_key: "legacy",
      device_id: "dev-legacy",
      public_key_pem: "public-key",
      private_key_pem: "legacy-plaintext-priv",
      created_at_ms: 1000,
      updated_at_ms: 1000,
    });

    const result = rotateDeviceIdentityWrappingKey({
      env,
      newProvider,
      newKeyId: "new-key-id",
    });

    expect(result.rotatedRows).toBe(0);

    const database = openOpenClawStateDatabase({ env });
    const row = database.db
      .prepare(
        "SELECT private_key_pem, private_key_wrapped FROM device_identities WHERE identity_key = 'legacy'",
      )
      .get() as { private_key_pem: string; private_key_wrapped: string | null };
    expect(row.private_key_pem).toBe("legacy-plaintext-priv");
    expect(row.private_key_wrapped).toBeNull();
  });

  it("rotates multiple rows with different from keyIds", () => {
    const { env } = useStateDir();
    const oldA = randomBytes(KEY_BYTES);
    const oldB = randomBytes(KEY_BYTES);
    const newKey = randomBytes(KEY_BYTES);
    const allKeys = new Map([
      ["old-a", oldA],
      ["old-b", oldB],
      ["new", newKey],
    ]);
    const newProvider = makeProvider("new", newKey, allKeys);
    const oldAProvider = makeProvider("old-a", oldA, allKeys);
    const oldBProvider = makeProvider("old-b", oldB, allKeys);

    insertDeviceIdentityRow(env, {
      identity_key: "row-a",
      device_id: "dev-a",
      public_key_pem: "pub",
      private_key_pem: "priv",
      private_key_wrapped: serializeWrappedSecret(wrapSecret(Buffer.from("a"), oldAProvider)),
      private_key_wrap_key_id: "old-a",
      created_at_ms: 1000,
      updated_at_ms: 1000,
    });
    insertDeviceIdentityRow(env, {
      identity_key: "row-b",
      device_id: "dev-b",
      public_key_pem: "pub",
      private_key_pem: "priv",
      private_key_wrapped: serializeWrappedSecret(wrapSecret(Buffer.from("b"), oldBProvider)),
      private_key_wrap_key_id: "old-b",
      created_at_ms: 2000,
      updated_at_ms: 2000,
    });

    const result = rotateDeviceIdentityWrappingKey({
      env,
      newProvider,
      newKeyId: "new",
      oldProvider: newProvider,
    });

    expect(result.rotatedRows).toBe(2);
    expect(result.fromKeyIds.size).toBe(2);
    expect(result.fromKeyIds.has("old-a")).toBe(true);
    expect(result.fromKeyIds.has("old-b")).toBe(true);
  });
});
