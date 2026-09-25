// Nostr plugin module implements channel.setup behavior.
import { describeAccountSnapshot } from "openclaw/plugin-sdk/account-helpers";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-contracts";
import {
  createDelegatedSetupWizardProxy,
  DEFAULT_ACCOUNT_ID,
} from "openclaw/plugin-sdk/setup-runtime";
import { buildChannelConfigSchema, type ChannelPlugin } from "./channel-api.js";
import { NostrConfigSchema } from "./config-schema.js";
import {
  createNostrSetupAdapter,
  createNostrSetupContract,
  createNostrSetupStatus,
} from "./setup-adapter.js";
import { resolveNostrAccount, type ResolvedNostrAccount } from "./types.js";

const channel = "nostr" as const;

type NostrAccountConfig = ResolvedNostrAccount["config"];

function getNostrConfig(cfg: OpenClawConfig): NostrAccountConfig | undefined {
  return (cfg.channels as Record<string, unknown> | undefined)?.nostr as
    | NostrAccountConfig
    | undefined;
}

function resolveDefaultSetupNostrAccountId(cfg: OpenClawConfig): string {
  const configured = getNostrConfig(cfg)?.defaultAccount;
  return typeof configured === "string" && configured.trim()
    ? configured.trim()
    : DEFAULT_ACCOUNT_ID;
}

function resolveSetupNostrAccount(params: {
  cfg: OpenClawConfig;
  accountId?: string | null;
}): ResolvedNostrAccount {
  return resolveNostrAccount({
    cfg: params.cfg,
    accountId: params.accountId?.trim() || resolveDefaultSetupNostrAccountId(params.cfg),
  });
}

const nostrSetupWizard = createDelegatedSetupWizardProxy({
  channel,
  loadWizard: async () => (await import("./setup-surface.js")).nostrSetupWizard,
  status: createNostrSetupStatus(resolveSetupNostrAccount),
  resolveShouldPromptAccountIds: () => false,
  delegatePrepare: true,
  delegateFinalize: true,
});

export const nostrSetupPlugin: ChannelPlugin<ResolvedNostrAccount> = {
  id: channel,
  meta: {
    id: channel,
    label: "Nostr",
    selectionLabel: "Nostr",
    docsPath: "/channels/nostr",
    docsLabel: "nostr",
    blurb: "OpenClaw post-quantum DMs via Nostr relays (ML-KEM-768 hybrid)",
    order: 100,
  },
  capabilities: {
    chatTypes: ["direct"],
    media: false,
  },
  reload: { configPrefixes: ["channels.nostr"] },
  configSchema: buildChannelConfigSchema(NostrConfigSchema),
  setupContract: createNostrSetupContract(
    createNostrSetupAdapter({
      resolveAccountId: (cfg, accountId) =>
        accountId?.trim() || resolveDefaultSetupNostrAccountId(cfg),
      validatePrivateKey: (privateKey) => /^(?:nsec1|NSEC1)|^[0-9a-fA-F]{64}$/u.test(privateKey),
    }),
  ),
  setupWizard: nostrSetupWizard,
  config: {
    listAccountIds: (cfg) =>
      resolveSetupNostrAccount({ cfg }).configured ? [resolveDefaultSetupNostrAccountId(cfg)] : [],
    resolveAccount: (cfg, accountId) => resolveSetupNostrAccount({ cfg, accountId }),
    defaultAccountId: resolveDefaultSetupNostrAccountId,
    isConfigured: (account) => account.configured,
    describeAccount: (account) =>
      describeAccountSnapshot({
        account,
        configured: account.configured,
        extra: {
          publicKey: account.publicKey,
          mlKemPublicKey: account.mlKemPublicKey,
        },
      }),
  },
};
