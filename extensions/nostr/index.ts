// Nostr plugin entrypoint registers its OpenClaw integration.
import {
  defineBundledChannelEntry,
  loadBundledEntryExportSync,
} from "openclaw/plugin-sdk/channel-entry-contract";
import type { OpenClawConfig, PluginRuntime, ResolvedNostrAccount } from "./api.js";

function createNostrProfileHttpHandler() {
  return loadBundledEntryExportSync<
    (params: Record<string, unknown>) => (ctx: unknown) => Promise<void> | void
  >(import.meta.url, {
    specifier: "./api.js",
    exportName: "createNostrProfileHttpHandler",
  });
}

function getNostrRuntime() {
  return loadBundledEntryExportSync<() => PluginRuntime>(import.meta.url, {
    specifier: "./api.js",
    exportName: "getNostrRuntime",
  })();
}

function updateActiveNostrPeerPqcKey() {
  return loadBundledEntryExportSync<
    (accountId: string, peerPubkey: string, publicKey: string) => boolean
  >(import.meta.url, {
    specifier: "./api.js",
    exportName: "updateActiveNostrPeerPqcKey",
  });
}

function readActiveNostrPeerPqcKey() {
  return loadBundledEntryExportSync<
    (accountId: string, peerPubkey: string) => { active: boolean; publicKey?: string }
  >(import.meta.url, {
    specifier: "./api.js",
    exportName: "readActiveNostrPeerPqcKey",
  });
}

function resolveNostrAccount(params: { cfg: unknown; accountId: string }) {
  return loadBundledEntryExportSync<
    (params: { cfg: unknown; accountId: string }) => ResolvedNostrAccount
  >(import.meta.url, {
    specifier: "./api.js",
    exportName: "resolveNostrAccount",
  })(params);
}

export default defineBundledChannelEntry({
  id: "nostr",
  name: "Nostr",
  description: "Nostr channel plugin for OpenClaw PQC direct messages",
  importMetaUrl: import.meta.url,
  plugin: {
    specifier: "./channel-plugin-api.js",
    exportName: "nostrPlugin",
  },
  runtime: {
    specifier: "./api.js",
    exportName: "setNostrRuntime",
  },
  registerFull(api) {
    const httpHandler = createNostrProfileHttpHandler()({
      getConfigProfile: (accountId: string) => {
        const runtime = getNostrRuntime();
        const cfg = runtime.config.current() as OpenClawConfig;
        const account = resolveNostrAccount({ cfg, accountId });
        return account.profile;
      },
      updateConfigProfile: async (_accountId: string, profile: unknown) => {
        const runtime = getNostrRuntime();

        await runtime.config.mutateConfigFile({
          afterWrite: { mode: "auto" },
          mutate: (draft) => {
            const channels = (draft.channels ?? {}) as Record<string, unknown>;
            const nostrConfig = (channels.nostr ?? {}) as Record<string, unknown>;

            draft.channels = {
              ...channels,
              nostr: {
                ...nostrConfig,
                profile,
              },
            };
          },
        });
      },
      getAccountInfo: (accountId: string) => {
        const runtime = getNostrRuntime();
        const cfg = runtime.config.current() as OpenClawConfig;
        const account = resolveNostrAccount({ cfg, accountId });
        if (!account.configured || !account.publicKey) {
          return null;
        }
        return {
          pubkey: account.publicKey,
          relays: account.relays,
        };
      },
      getPinnedPqcKey: (accountId: string, peerPubkey: string) => {
        const activePin = readActiveNostrPeerPqcKey()(accountId, peerPubkey);
        if (activePin.active) {
          return activePin.publicKey;
        }
        const runtime = getNostrRuntime();
        const cfg = runtime.config.current() as OpenClawConfig;
        const account = resolveNostrAccount({ cfg, accountId });
        return account.mlKemPeerPublicKeys[peerPubkey];
      },
      updatePinnedPqcKey: async (
        accountId: string,
        peerPubkey: string,
        publicKey: string,
        expectedCurrentKey: string | null,
      ) => {
        const runtime = getNostrRuntime();
        let updated = false;
        let appliedToBus = false;
        await runtime.config.mutateConfigFile({
          // Apply only after persistence succeeds. If no bus accepted the key,
          // keep normal Nostr reload behavior instead of claiming a no-op.
          afterWrite: {
            mode: "auto",
            applyInPlace: () => {
              if (!updated) {
                return [];
              }
              appliedToBus = updateActiveNostrPeerPqcKey()(accountId, peerPubkey, publicKey);
              return appliedToBus ? [`channels.nostr.mlKemPeerPublicKeys.${peerPubkey}`] : [];
            },
          },
          mutate: (draft) => {
            const channels = (draft.channels ?? {}) as Record<string, unknown>;
            const nostrConfig = (channels.nostr ?? {}) as Record<string, unknown>;
            const currentPins = {
              ...((nostrConfig.mlKemPeerPublicKeys ?? {}) as Record<string, string>),
            };
            if ((currentPins[peerPubkey] ?? null) !== expectedCurrentKey) {
              return;
            }
            currentPins[peerPubkey] = publicKey;
            draft.channels = {
              ...channels,
              nostr: {
                ...nostrConfig,
                mlKemPeerPublicKeys: currentPins,
              },
            };
            updated = true;
          },
        });
        return updated ? (appliedToBus ? true : "pending") : false;
      },
      log: api.logger,
    });

    api.registerHttpRoute({
      path: "/api/channels/nostr",
      auth: "gateway",
      match: "prefix",
      gatewayRuntimeScopeSurface: "trusted-operator",
      handler: httpHandler,
    });
  },
});
