import { openClawPqcDm } from "openclaw/plugin-sdk/security-runtime";
// Nostr plugin module implements test fixtures behavior.
import type { ResolvedNostrAccount } from "./types.js";

export const TEST_HEX_PRIVATE_KEY =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

export const TEST_HEX_PUBLIC_KEY =
  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

export const TEST_RELAY_URL = "wss://relay.example.com";
export const TEST_SETUP_RELAY_URLS = ["wss://relay.damus.io", "wss://relay.primal.net"];
export const TEST_RESOLVED_PRIVATE_KEY = "resolved-nostr-private-key";

const TEST_ML_KEM_KEY_PAIR = openClawPqcDm.generateMlKem768KeyPair();
export const TEST_ML_KEM_SECRET_KEY = openClawPqcDm.encodeMlKemKey(TEST_ML_KEM_KEY_PAIR.secretKey);
export const TEST_ML_KEM_PUBLIC_KEY = openClawPqcDm.encodeMlKemKey(TEST_ML_KEM_KEY_PAIR.publicKey);

export const TEST_HEX_PRIVATE_KEY_BYTES = new Uint8Array(
  TEST_HEX_PRIVATE_KEY.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)),
);

export function createConfiguredNostrCfg(overrides: Record<string, unknown> = {}): {
  channels: { nostr: Record<string, unknown> };
} {
  return {
    channels: {
      nostr: {
        privateKey: TEST_HEX_PRIVATE_KEY,
        mlKemSecretKey: TEST_ML_KEM_SECRET_KEY,
        ...overrides,
      },
    },
  };
}

export function buildResolvedNostrAccount(
  overrides: Partial<ResolvedNostrAccount> = {},
): ResolvedNostrAccount {
  return {
    accountId: "default",
    enabled: true,
    configured: true,
    privateKey: TEST_HEX_PRIVATE_KEY,
    publicKey: TEST_HEX_PUBLIC_KEY,
    mlKemSecretKey: TEST_ML_KEM_SECRET_KEY,
    mlKemPublicKey: TEST_ML_KEM_PUBLIC_KEY,
    mlKemPeerPublicKeys: {},
    relays: [TEST_RELAY_URL],
    config: {},
    ...overrides,
  };
}
