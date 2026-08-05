import { afterEach, describe, expect, it } from "vitest";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { withTempDir } from "../test-utils/temp-dir.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
  type DeviceIdentityStoreOptions,
} from "./device-identity-store.js";

const KEY_ID = "test-wrap-key";
const KEY_BYTES = Buffer.alloc(32, 7);

function makeProvider(): WrappingKeyProvider {
  return {
    getActiveKey: () => ({ key: KEY_BYTES, keyId: KEY_ID }),
    getKeyById: (id) => (id === KEY_ID ? KEY_BYTES : null),
  };
}

function storeOptions(rootDir: string): DeviceIdentityStoreOptions {
  return {
    env: { ...process.env, OPENCLAW_STATE_DIR: rootDir },
    path: `${rootDir}/state/openclaw.sqlite`,
  };
}

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
});

describe("device-identity-store AES-256-GCM wrapping round-trip", () => {
  it("insert + read with wrappingProvider preserves Ed25519 + ML-DSA-65 private keys", async () => {
    await withTempDir("device-identity-wrap-", async (rootDir) => {
      const provider = makeProvider();
      const candidate = generateStoredDeviceIdentity();
      const inserted = insertStoredDeviceIdentityIfAbsent(candidate, {
        ...storeOptions(rootDir),
        wrappingProvider: provider,
      });
      expect(inserted.publicKeyPem).toBe(candidate.publicKeyPem);
      expect(inserted.privateKeyPem).toBe(candidate.privateKeyPem);
      expect(inserted.mldsaPublicKeyPem).toBe(candidate.mldsaPublicKeyPem);
      expect(inserted.mldsaPrivateKeyPem).toBe(candidate.mldsaPrivateKeyPem);

      const read = readStoredDeviceIdentity({
        ...storeOptions(rootDir),
        wrappingProvider: provider,
      });
      expect(read).not.toBeNull();
      expect(read!.publicKeyPem).toBe(candidate.publicKeyPem);
      expect(read!.privateKeyPem).toBe(candidate.privateKeyPem);
      expect(read!.mldsaPublicKeyPem).toBe(candidate.mldsaPublicKeyPem);
      expect(read!.mldsaPrivateKeyPem).toBe(candidate.mldsaPrivateKeyPem);
    });
  });

  it("reading without wrappingProvider still works (legacy plaintext column)", async () => {
    await withTempDir("device-identity-wrap-", async (rootDir) => {
      const provider = makeProvider();
      const candidate = generateStoredDeviceIdentity();
      insertStoredDeviceIdentityIfAbsent(candidate, {
        ...storeOptions(rootDir),
        wrappingProvider: provider,
      });
      // No wrappingProvider passed: should fall back to legacy private_key_pem column
      const read = readStoredDeviceIdentity(storeOptions(rootDir));
      expect(read).not.toBeNull();
      expect(read!.privateKeyPem).toBe(candidate.privateKeyPem);
      expect(read!.mldsaPrivateKeyPem).toBe(candidate.mldsaPrivateKeyPem);
    });
  });

  it("reading with wrong wrappingProvider key throws (cannot decrypt)", async () => {
    await withTempDir("device-identity-wrap-", async (rootDir) => {
      const provider = makeProvider();
      const candidate = generateStoredDeviceIdentity();
      insertStoredDeviceIdentityIfAbsent(candidate, {
        ...storeOptions(rootDir),
        wrappingProvider: provider,
      });
      const wrongKey = Buffer.alloc(32, 99);
      const wrongProvider: WrappingKeyProvider = {
        getActiveKey: () => ({ key: wrongKey, keyId: KEY_ID }),
        getKeyById: () => wrongKey, // keyId matches but key bytes differ
      };
      expect(() => readStoredDeviceIdentity({
        ...storeOptions(rootDir),
        wrappingProvider: wrongProvider,
      })).toThrow();
    });
  });

  it("re-insert with same identity key is a no-op when wrapped data already exists", async () => {
    await withTempDir("device-identity-wrap-", async (rootDir) => {
      const provider = makeProvider();
      const candidate = generateStoredDeviceIdentity();
      const first = insertStoredDeviceIdentityIfAbsent(candidate, {
        ...storeOptions(rootDir),
        wrappingProvider: provider,
      });
      const second = insertStoredDeviceIdentityIfAbsent(candidate, {
        ...storeOptions(rootDir),
        wrappingProvider: provider,
      });
      expect(second.deviceId).toBe(first.deviceId);
      expect(second.privateKeyPem).toBe(candidate.privateKeyPem);
      expect(second.mldsaPrivateKeyPem).toBe(candidate.mldsaPrivateKeyPem);
    });
  });
});
