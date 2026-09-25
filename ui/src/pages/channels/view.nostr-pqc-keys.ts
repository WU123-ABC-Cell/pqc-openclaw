// Nostr PQC peer-key management. Relay announcements remain untrusted until an
// operator confirms the complete fingerprint through an independent channel.
import { html, nothing, type TemplateResult } from "lit";
import { renderSettingsStatus } from "../../components/settings-ui.ts";
import { t } from "../../i18n/index.ts";
import type { NostrPqcKeyDiscovery, NostrPqcTrustState } from "./nostr-profile-ops.ts";

export type NostrPqcKeyPanelState = {
  peerPubkey: string;
  confirmedFingerprint: string;
  publishedFingerprint: string | null;
  discovery: NostrPqcKeyDiscovery | null;
  discovering: boolean;
  pinning: boolean;
  publishing: boolean;
  error: string | null;
  notice: string | null;
};

export type NostrPqcKeyPanelCallbacks = {
  onPeerPubkeyChange: (value: string) => void;
  onConfirmedFingerprintChange: (value: string) => void;
  onDiscover: () => void;
  onPin: () => void;
  onPublish: () => void;
};

export function createNostrPqcKeyPanelState(): NostrPqcKeyPanelState {
  return {
    peerPubkey: "",
    confirmedFingerprint: "",
    publishedFingerprint: null,
    discovery: null,
    discovering: false,
    pinning: false,
    publishing: false,
    error: null,
    notice: null,
  };
}

function trustStatus(trustState: NostrPqcTrustState) {
  switch (trustState) {
    case "pinned":
      return { kind: "ok" as const, label: t("channels.nostr.pqcKeys.states.pinned") };
    case "untrusted-first-key":
      return { kind: "warn" as const, label: t("channels.nostr.pqcKeys.states.firstKey") };
    case "untrusted-rotation":
      return { kind: "warn" as const, label: t("channels.nostr.pqcKeys.states.rotation") };
    case "rotation-chain-mismatch":
      return { kind: "danger" as const, label: t("channels.nostr.pqcKeys.states.mismatch") };
    case "not-found":
      return { kind: "muted" as const, label: t("channels.nostr.pqcKeys.states.notFound") };
  }
}

function renderFingerprint(label: string, value: string | null | undefined): TemplateResult {
  return html`
    <div class="settings-row settings-row--stacked">
      <div class="settings-row__text">
        <span class="settings-row__title">${label}</span>
      </div>
      <div class="settings-row__control">
        <code style="overflow-wrap: anywhere; user-select: all;">${value ?? t("common.na")}</code>
      </div>
    </div>
  `;
}

export function renderNostrPqcKeyPanel(params: {
  state: NostrPqcKeyPanelState;
  callbacks: NostrPqcKeyPanelCallbacks;
  canAdmin: boolean;
  configured: boolean;
}): TemplateResult {
  const { state, callbacks, canAdmin, configured } = params;
  const candidate = state.discovery?.announcement ?? null;
  const status = state.discovery ? trustStatus(state.discovery.trustState) : null;
  const canPinState =
    state.discovery?.trustState === "untrusted-first-key" ||
    state.discovery?.trustState === "untrusted-rotation";
  const fingerprintMatches =
    candidate !== null && state.confirmedFingerprint.trim() === candidate.fingerprint;
  const busy = state.discovering || state.pinning || state.publishing;

  return html`
    <div class="settings-row">
      <div class="settings-row__text">
        <span class="settings-row__title">${t("channels.nostr.pqcKeys.title")}</span>
        <span class="settings-row__desc">${t("channels.nostr.pqcKeys.description")}</span>
      </div>
      <div class="settings-row__control">
        <button
          class="btn btn--sm"
          @click=${callbacks.onPublish}
          ?disabled=${busy || !canAdmin || !configured}
          title=${!canAdmin ? t("channels.nostr.pqcKeys.adminRequired") : ""}
        >
          ${state.publishing
            ? t("channels.nostr.pqcKeys.publishing")
            : t("channels.nostr.pqcKeys.publishLocal")}
        </button>
      </div>
    </div>

    ${state.error
      ? html`
          <div class="settings-row">
            <div class="settings-row__text">
              <span class="settings-row__title">
                ${renderSettingsStatus({ kind: "danger", label: t("channels.lastError") })}
              </span>
              <span class="settings-row__desc">${state.error}</span>
            </div>
          </div>
        `
      : nothing}
    ${state.notice
      ? html`
          <div class="settings-row">
            <div class="settings-row__text">
              <span class="settings-row__desc">${state.notice}</span>
            </div>
          </div>
        `
      : nothing}
    ${state.publishedFingerprint
      ? renderFingerprint(t("channels.nostr.pqcKeys.localFingerprint"), state.publishedFingerprint)
      : nothing}

    <div class="settings-row settings-row--stacked">
      <div class="settings-row__text">
        <label class="settings-row__title" for="nostr-pqc-peer-pubkey">
          ${t("channels.nostr.pqcKeys.peerPubkey")}
        </label>
        <span class="settings-row__desc">${t("channels.nostr.pqcKeys.peerPubkeyHelp")}</span>
      </div>
      <div class="settings-row__control">
        <input
          id="nostr-pqc-peer-pubkey"
          class="settings-input"
          type="text"
          autocomplete="off"
          spellcheck="false"
          .value=${state.peerPubkey}
          placeholder=${t("channels.nostr.pqcKeys.peerPubkeyPlaceholder")}
          @input=${(event: InputEvent) =>
            callbacks.onPeerPubkeyChange((event.target as HTMLInputElement).value)}
          ?disabled=${busy}
        />
        <button
          class="btn"
          @click=${callbacks.onDiscover}
          ?disabled=${busy || !configured || state.peerPubkey.trim().length === 0}
        >
          ${state.discovering
            ? t("channels.nostr.pqcKeys.discovering")
            : t("channels.nostr.pqcKeys.discover")}
        </button>
      </div>
    </div>

    ${state.discovery
      ? html`
          <div class="settings-row">
            <div class="settings-row__text">
              <span class="settings-row__title">${t("channels.nostr.pqcKeys.trustState")}</span>
            </div>
            <div class="settings-row__control">
              ${status ? renderSettingsStatus(status) : nothing}
            </div>
          </div>
          ${renderFingerprint(
            t("channels.nostr.pqcKeys.pinnedFingerprint"),
            state.discovery.pinnedFingerprint,
          )}
          ${candidate
            ? html`
                ${renderFingerprint(
                  t("channels.nostr.pqcKeys.candidateFingerprint"),
                  candidate.fingerprint,
                )}
                ${candidate.previousFingerprint
                  ? renderFingerprint(
                      t("channels.nostr.pqcKeys.previousFingerprint"),
                      candidate.previousFingerprint,
                    )
                  : nothing}
                <div class="settings-row">
                  <div class="settings-row__text">
                    <span class="settings-row__title">${t("channels.nostr.pqcKeys.sources")}</span>
                    <span class="settings-row__desc">
                      ${state.discovery.sourceRelays.length > 0
                        ? state.discovery.sourceRelays.join(", ")
                        : t("common.na")}
                    </span>
                  </div>
                  <div class="settings-row__control">
                    <span class="settings-row__value">
                      ${new Date(candidate.createdAt * 1000).toLocaleString()}
                    </span>
                  </div>
                </div>
              `
            : html`
                <div class="settings-row">
                  <div class="settings-row__text">
                    <span class="settings-row__desc">
                      ${t("channels.nostr.pqcKeys.notFoundHelp")}
                    </span>
                  </div>
                </div>
              `}
          ${state.discovery.trustState === "rotation-chain-mismatch"
            ? html`
                <div class="settings-row">
                  <div class="settings-row__text">
                    <span class="settings-row__title" style="color: var(--danger);">
                      ${t("channels.nostr.pqcKeys.rotationBlocked")}
                    </span>
                    <span class="settings-row__desc">
                      ${t("channels.nostr.pqcKeys.rotationBlockedHelp")}
                    </span>
                  </div>
                </div>
              `
            : nothing}
          ${canPinState && candidate
            ? html`
                <div class="settings-row settings-row--stacked">
                  <div class="settings-row__text">
                    <label class="settings-row__title" for="nostr-pqc-confirmed-fingerprint">
                      ${t("channels.nostr.pqcKeys.confirmedFingerprint")}
                    </label>
                    <span class="settings-row__desc">
                      ${t("channels.nostr.pqcKeys.confirmedFingerprintHelp")}
                    </span>
                  </div>
                  <div class="settings-row__control">
                    <input
                      id="nostr-pqc-confirmed-fingerprint"
                      class="settings-input"
                      type="text"
                      autocomplete="off"
                      spellcheck="false"
                      .value=${state.confirmedFingerprint}
                      placeholder="sha256:…"
                      @input=${(event: InputEvent) =>
                        callbacks.onConfirmedFingerprintChange(
                          (event.target as HTMLInputElement).value,
                        )}
                      ?disabled=${busy || !canAdmin}
                    />
                    <button
                      class="btn primary"
                      @click=${callbacks.onPin}
                      ?disabled=${busy || !canAdmin || !fingerprintMatches}
                      title=${!canAdmin ? t("channels.nostr.pqcKeys.adminRequired") : ""}
                    >
                      ${state.pinning
                        ? t("channels.nostr.pqcKeys.pinning")
                        : state.discovery.trustState === "untrusted-rotation"
                          ? t("channels.nostr.pqcKeys.confirmRotation")
                          : t("channels.nostr.pqcKeys.pinKey")}
                    </button>
                  </div>
                </div>
              `
            : nothing}
        `
      : nothing}
  `;
}
