import { createAccountListHelpers } from "openclaw/plugin-sdk/account-helpers";
// Nostr type declarations define plugin contracts.
import {
  DEFAULT_ACCOUNT_ID,
  normalizeAccountId,
  normalizeOptionalAccountId,
} from "openclaw/plugin-sdk/account-id";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-contracts";
import { normalizeSecretInputString, type SecretInput } from "openclaw/plugin-sdk/secret-input";
import { openClawPqcDm } from "openclaw/plugin-sdk/security-runtime";
import { normalizeOptionalString } from "openclaw/plugin-sdk/string-coerce-runtime";
import type { NostrProfile } from "./config-schema.js";
import { DEFAULT_RELAYS } from "./default-relays.js";
import { getPublicKeyFromPrivate } from "./nostr-key-utils.js";

const { decodeMlKem768SecretKey, deriveMlKem768PublicKey, encodeMlKemKey } = openClawPqcDm;

interface NostrAccountConfig {
  enabled?: boolean;
  name?: string;
  defaultAccount?: string;
  privateKey?: SecretInput;
  mlKemSecretKey?: SecretInput;
  mlKemPeerPublicKeys?: Record<string, string>;
  relays?: string[];
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  allowFrom?: Array<string | number>;
  profile?: NostrProfile;
}

export interface ResolvedNostrAccount {
  accountId: string;
  name?: string;
  enabled: boolean;
  configured: boolean;
  privateKey: string;
  publicKey: string;
  mlKemSecretKey: string;
  mlKemPublicKey: string;
  mlKemPeerPublicKeys: Record<string, string>;
  relays: string[];
  profile?: NostrProfile;
  config: NostrAccountConfig;
}

const {
  listAccountIds: listNostrAccountIds,
  resolveDefaultAccountId: resolveDefaultNostrAccountId,
} = createAccountListHelpers("nostr", {
  fallbackAccountIdWhenEmpty: false,
  resolveImplicitAccountId: (cfg) => {
    const account = cfg.channels?.nostr as NostrAccountConfig | undefined;
    return normalizeSecretInputString(account?.privateKey)
      ? (normalizeOptionalAccountId(account?.defaultAccount) ?? DEFAULT_ACCOUNT_ID)
      : undefined;
  },
});

export { listNostrAccountIds, resolveDefaultNostrAccountId };

/**
 * Resolve a Nostr account from config
 */
export function resolveNostrAccount(opts: {
  cfg: OpenClawConfig;
  accountId?: string | null;
}): ResolvedNostrAccount {
  const accountId = normalizeAccountId(opts.accountId ?? resolveDefaultNostrAccountId(opts.cfg));
  const nostrCfg = (opts.cfg.channels as Record<string, unknown> | undefined)?.nostr as
    | NostrAccountConfig
    | undefined;

  const baseEnabled = nostrCfg?.enabled !== false;
  const privateKey = normalizeSecretInputString(nostrCfg?.privateKey) ?? "";
  const mlKemSecretKey = normalizeSecretInputString(nostrCfg?.mlKemSecretKey) ?? "";

  let publicKey = "";
  if (privateKey) {
    try {
      publicKey = getPublicKeyFromPrivate(privateKey);
    } catch {
      // Invalid key - leave publicKey empty, configured will indicate issues
    }
  }

  let mlKemPublicKey = "";
  if (mlKemSecretKey) {
    let secretKey: Uint8Array | undefined;
    try {
      secretKey = decodeMlKem768SecretKey(mlKemSecretKey);
      mlKemPublicKey = encodeMlKemKey(deriveMlKem768PublicKey(secretKey));
    } catch {
      // Invalid key - leave public key empty so configured remains false.
    } finally {
      secretKey?.fill(0);
    }
  }
  const mlKemPeerPublicKeys = { ...nostrCfg?.mlKemPeerPublicKeys };
  const configured = Boolean(privateKey && publicKey && mlKemSecretKey && mlKemPublicKey);

  return {
    accountId,
    name: normalizeOptionalString(nostrCfg?.name),
    enabled: baseEnabled,
    configured,
    privateKey,
    publicKey,
    mlKemSecretKey,
    mlKemPublicKey,
    mlKemPeerPublicKeys,
    relays: nostrCfg?.relays ?? DEFAULT_RELAYS,
    profile: nostrCfg?.profile,
    config: {
      enabled: nostrCfg?.enabled,
      name: nostrCfg?.name,
      privateKey: nostrCfg?.privateKey,
      mlKemSecretKey: nostrCfg?.mlKemSecretKey,
      mlKemPeerPublicKeys: nostrCfg?.mlKemPeerPublicKeys,
      relays: nostrCfg?.relays,
      dmPolicy: nostrCfg?.dmPolicy,
      allowFrom: nostrCfg?.allowFrom,
      profile: nostrCfg?.profile,
    },
  };
}
