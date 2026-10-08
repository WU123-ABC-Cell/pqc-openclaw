/* @vitest-environment node */

import { webcrypto } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  deriveDeviceIdFromPublicKey,
  MLDSA65_PUBLIC_KEY_LENGTH,
  MLDSA65_SECRET_KEY_LENGTH,
  verifyDeviceSignature,
} from "../../../../src/infra/device-identity.js";
import { createStorageMock } from "../../test-helpers/storage.ts";
import {
  loadDeviceAuthToken,
  loadOrCreateDeviceIdentity,
  peekStoredDeviceIdentityId,
  signDevicePayload,
  storeDeviceAuthToken,
} from "./index.ts";

const identityKey = "openclaw-device-identity-v2";
const legacyIdentityKey = "openclaw-device-identity-v1";

beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  vi.stubGlobal("localStorage", createStorageMock());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Control UI device identity", () => {
  it("generates a persistent ML-DSA-65 identity accepted by the Gateway verifier", async () => {
    const identity = await loadOrCreateDeviceIdentity();
    const payload = "v2|browser-device|connect.challenge";
    const signature = await signDevicePayload(identity.privateKey, payload);

    expect(Buffer.from(identity.publicKey, "base64url")).toHaveLength(MLDSA65_PUBLIC_KEY_LENGTH);
    expect(Buffer.from(identity.privateKey, "base64url")).toHaveLength(MLDSA65_SECRET_KEY_LENGTH);
    expect(Buffer.from(signature, "base64url")).toHaveLength(3309);
    expect(
      ml_dsa65.verify(
        Buffer.from(signature, "base64url"),
        new TextEncoder().encode(payload),
        Buffer.from(identity.publicKey, "base64url"),
      ),
    ).toBe(true);
    expect(deriveDeviceIdFromPublicKey(identity.publicKey)).toBe(identity.deviceId);
    expect(verifyDeviceSignature(identity.publicKey, payload, signature)).toBe(true);
    expect(verifyDeviceSignature(identity.publicKey, `${payload}|tampered`, signature)).toBe(false);
    expect(peekStoredDeviceIdentityId()).toBe(identity.deviceId);
    expect(await loadOrCreateDeviceIdentity()).toEqual(identity);
  });

  it("replaces a stored Ed25519 identity without reusing its scoped device token", async () => {
    const oldDeviceId = "a".repeat(64);
    localStorage.setItem(
      legacyIdentityKey,
      JSON.stringify({
        version: 1,
        deviceId: oldDeviceId,
        publicKey: "AA",
        privateKey: "AA",
        createdAtMs: 1,
      }),
    );
    const tokenParams = {
      deviceId: oldDeviceId,
      gatewayUrl: "wss://gateway.example",
      role: "operator",
    };
    storeDeviceAuthToken({ ...tokenParams, token: "old-device-token" });
    expect(peekStoredDeviceIdentityId()).toBeNull();

    const identity = await loadOrCreateDeviceIdentity();
    expect(identity.deviceId).not.toBe(oldDeviceId);
    expect(localStorage.getItem(legacyIdentityKey)).toBeNull();
    expect(JSON.parse(localStorage.getItem(identityKey) ?? "null").version).toBe(2);
    expect(loadDeviceAuthToken(tokenParams)).toBeNull();
    expect(loadDeviceAuthToken({ ...tokenParams, deviceId: identity.deviceId })).toBeNull();
    expect(await loadOrCreateDeviceIdentity()).toEqual(identity);
  });

  it("replaces a persisted identity whose public and secret keys do not match", async () => {
    const identity = await loadOrCreateDeviceIdentity();
    const stored = JSON.parse(localStorage.getItem(identityKey) ?? "null");
    stored.privateKey = Buffer.from(ml_dsa65.keygen().secretKey).toString("base64url");
    localStorage.setItem(identityKey, JSON.stringify(stored));

    const replacement = await loadOrCreateDeviceIdentity();
    expect(replacement.deviceId).not.toBe(identity.deviceId);
    expect(deriveDeviceIdFromPublicKey(replacement.publicKey)).toBe(replacement.deviceId);
  });

  it("fails visibly instead of using an identity that could not be persisted", async () => {
    const storage = createStorageMock();
    storage.setItem = () => {
      throw new Error("storage denied");
    };
    vi.stubGlobal("localStorage", storage);

    await expect(loadOrCreateDeviceIdentity()).rejects.toThrow(
      "Could not save browser device identity",
    );
    expect(peekStoredDeviceIdentityId()).toBeNull();
  });

  it("preserves the old identity and token when migration cannot save the replacement", async () => {
    const oldDeviceId = "b".repeat(64);
    localStorage.setItem(
      legacyIdentityKey,
      JSON.stringify({ version: 1, deviceId: oldDeviceId, publicKey: "AA", privateKey: "AA" }),
    );
    const tokenParams = {
      deviceId: oldDeviceId,
      gatewayUrl: "wss://gateway.example",
      role: "operator",
    };
    storeDeviceAuthToken({ ...tokenParams, token: "old-device-token" });
    const setItem = localStorage.setItem.bind(localStorage);
    localStorage.setItem = (key, value) => {
      if (key === identityKey) {
        throw new Error("storage denied");
      }
      setItem(key, value);
    };

    await expect(loadOrCreateDeviceIdentity()).rejects.toThrow(
      "Could not save browser device identity",
    );
    expect(localStorage.getItem(legacyIdentityKey)).not.toBeNull();
    expect(loadDeviceAuthToken(tokenParams)?.token).toBe("old-device-token");
    expect(localStorage.getItem(identityKey)).toBeNull();
  });
});
