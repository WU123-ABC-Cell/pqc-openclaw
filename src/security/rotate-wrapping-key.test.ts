// PQC step 2.3.5.C: unit tests for rotation helpers.
import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
  rewrapAll,
  rewrapDeviceIdentityRow,
  rewrapStoredSecret,
  type WrappedKeyPair,
} from "./rotate-wrapping-key.js";
import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  unwrapSecret,
  wrapSecret,
  type ActiveWrappingKey,
  type WrappingKeyProvider,
} from "./secret-wrapping.js";

const KEY_BYTES = 32;

function makeProvider(keyId: string, key?: Buffer): WrappingKeyProvider {
  const _key = key ?? randomBytes(KEY_BYTES);
  return {
    getActiveKey: (): ActiveWrappingKey => ({ key: _key, keyId }),
    getKeyById: (id: string) => (id === keyId ? _key : null),
  };
}

/** A provider that knows multiple keys. The first one in the map is "active". */
function makeMultiProvider(keys: Map<string, Buffer>): WrappingKeyProvider {
  const first = keys.entries().next().value as [string, Buffer];
  return {
    getActiveKey: (): ActiveWrappingKey => ({ key: first[1], keyId: first[0] }),
    getKeyById: (id: string) => keys.get(id) ?? null,
  };
}

describe("rewrapStoredSecret", () => {
  it("returns unchanged for null pair", () => {
    const r = rewrapStoredSecret({ wrapped: null, wrapKeyId: null }, makeProvider("new"), "new");
    expect(r).toEqual({ wrapped: null, wrapKeyId: null, changed: false });
  });

  it("returns unchanged when keyId matches and no oldProvider", () => {
    const p = makeProvider("same");
    const wrapped = serializeWrappedSecret(wrapSecret(Buffer.from("hello"), p));
    const r = rewrapStoredSecret({ wrapped, wrapKeyId: "same" }, p, "same");
    expect(r).toEqual({ wrapped, wrapKeyId: "same", changed: false });
  });

  it("re-wraps when keyId changes (verifies with new key)", () => {
    const oldKey = randomBytes(KEY_BYTES);
    const newKey = randomBytes(KEY_BYTES);
    const provider = makeMultiProvider(new Map([
      ["old", oldKey],
      ["new", newKey],
    ]));
    const plaintext = Buffer.from("secret-data");
    const wrapped = serializeWrappedSecret(wrapSecret(plaintext, provider));

    const r = rewrapStoredSecret({ wrapped, wrapKeyId: "old" }, provider, "new", provider);
    expect(r.changed).toBe(true);
    expect(r.wrapKeyId).toBe("new");

    const unwrapped = unwrapSecret(deserializeWrappedSecret(r.wrapped!), provider);
    expect(unwrapped.equals(plaintext)).toBe(true);
  });

  it("re-wraps using explicit oldProvider even if keyId matches", () => {
    const oldKey = randomBytes(KEY_BYTES);
    const newKey = randomBytes(KEY_BYTES);
    const old = makeProvider("old", oldKey);
    const next = makeProvider("new", newKey);
    const plaintext = Buffer.from("secret");
    const wrapped = serializeWrappedSecret(wrapSecret(plaintext, old));

    const r = rewrapStoredSecret({ wrapped, wrapKeyId: "old" }, next, "old", old);
    expect(r.changed).toBe(true);
    expect(r.wrapKeyId).toBe("old");
  });
});

describe("rewrapAll", () => {
  it("returns count of changed rows", () => {
    const oldKey = randomBytes(KEY_BYTES);
    const newKey = randomBytes(KEY_BYTES);
    const provider = makeMultiProvider(new Map([
      ["old", oldKey],
      ["new", newKey],
    ]));

    const rows: WrappedKeyPair[] = [
      { wrapped: serializeWrappedSecret(wrapSecret(Buffer.from("a"), provider)), wrapKeyId: "old" },
      { wrapped: null, wrapKeyId: null },
      { wrapped: serializeWrappedSecret(wrapSecret(Buffer.from("c"), provider)), wrapKeyId: "old" },
    ];

    const { results, rotated } = rewrapAll(rows, provider, "new", provider);
    expect(rotated).toBe(2);
    expect(results[0].changed).toBe(true);
    expect(results[1].changed).toBe(false);
    expect(results[2].changed).toBe(true);
  });
});

describe("rewrapDeviceIdentityRow", () => {
  it("rewraps both Ed25519 and ML-DSA-65 wrap columns", () => {
    const oldKey = randomBytes(KEY_BYTES);
    const newKey = randomBytes(KEY_BYTES);
    const provider = makeMultiProvider(new Map([
      ["old", oldKey],
      ["new", newKey],
    ]));

    const ed25519Plain = Buffer.from("ed25519-private");
    const mldsaPlain = Buffer.from("mldsa-private");

    const row = {
      identity_key: "primary",
      private_key_wrapped: serializeWrappedSecret(wrapSecret(ed25519Plain, provider)),
      private_key_wrap_key_id: "old",
      mldsa_private_key_wrapped: serializeWrappedSecret(wrapSecret(mldsaPlain, provider)),
      mldsa_private_key_wrap_key_id: "old",
    };

    const r = rewrapDeviceIdentityRow(row, provider, "new", provider);
    expect(r.changed).toBe(true);
    expect(r.ed25519.wrapKeyId).toBe("new");
    expect(r.mldsa.wrapKeyId).toBe("new");

    const ed = unwrapSecret(deserializeWrappedSecret(r.ed25519.wrapped!), provider);
    const ml = unwrapSecret(deserializeWrappedSecret(r.mldsa.wrapped!), provider);
    expect(ed.equals(ed25519Plain)).toBe(true);
    expect(ml.equals(mldsaPlain)).toBe(true);
  });

  it("skips when both wrap columns are null (legacy plaintext)", () => {
    const r = rewrapDeviceIdentityRow(
      {
        identity_key: "primary",
        private_key_wrapped: null,
        private_key_wrap_key_id: null,
        mldsa_private_key_wrapped: null,
        mldsa_private_key_wrap_key_id: null,
      },
      makeProvider("new"),
      "new",
    );
    expect(r.changed).toBe(false);
    expect(r.ed25519.wrapped).toBeNull();
    expect(r.mldsa.wrapped).toBeNull();
  });

  it("rewraps only the Ed25519 wrap when ML-DSA is null", () => {
    const oldKey = randomBytes(KEY_BYTES);
    const newKey = randomBytes(KEY_BYTES);
    const provider = makeMultiProvider(new Map([
      ["old", oldKey],
      ["new", newKey],
    ]));

    const r = rewrapDeviceIdentityRow(
      {
        identity_key: "primary",
        private_key_wrapped: serializeWrappedSecret(wrapSecret(Buffer.from("ed"), provider)),
        private_key_wrap_key_id: "old",
        mldsa_private_key_wrapped: null,
        mldsa_private_key_wrap_key_id: null,
      },
      provider,
      "new",
      provider,
    );
    expect(r.changed).toBe(true);
    expect(r.ed25519.changed).toBe(true);
    expect(r.mldsa.changed).toBe(false);
  });
});
