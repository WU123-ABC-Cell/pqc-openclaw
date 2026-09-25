/* @vitest-environment jsdom */
import { render } from "lit";
import { describe, expect, it, vi } from "vitest";
import {
  createNostrPqcKeyPanelState,
  renderNostrPqcKeyPanel,
  type NostrPqcKeyPanelCallbacks,
  type NostrPqcKeyPanelState,
} from "./view.nostr-pqc-keys.ts";

const CANDIDATE_FINGERPRINT = `sha256:${"a".repeat(64)}`;
const PINNED_FINGERPRINT = `sha256:${"b".repeat(64)}`;

function renderPanel(
  overrides: Partial<NostrPqcKeyPanelState> = {},
  options: { canAdmin?: boolean; callbacks?: Partial<NostrPqcKeyPanelCallbacks> } = {},
) {
  const state: NostrPqcKeyPanelState = {
    ...createNostrPqcKeyPanelState(),
    peerPubkey: "npub1peer",
    discovery: {
      peerPubkey: "f".repeat(64),
      pinnedFingerprint: null,
      trustState: "untrusted-first-key",
      announcement: {
        eventId: "event-id",
        pubkey: "f".repeat(64),
        createdAt: 1_800_000_000,
        publicKey: "base64-key",
        fingerprint: CANDIDATE_FINGERPRINT,
      },
      relaysQueried: ["wss://relay.example"],
      sourceRelays: ["wss://relay.example"],
    },
    ...overrides,
  };
  const callbacks: NostrPqcKeyPanelCallbacks = {
    onPeerPubkeyChange: vi.fn(),
    onConfirmedFingerprintChange: vi.fn(),
    onDiscover: vi.fn(),
    onPin: vi.fn(),
    onPublish: vi.fn(),
    ...options.callbacks,
  };
  const container = document.createElement("div");
  render(
    renderNostrPqcKeyPanel({
      state,
      callbacks,
      canAdmin: options.canAdmin ?? true,
      configured: true,
    }),
    container,
  );
  return { container, callbacks };
}

describe("Nostr PQC key panel", () => {
  it("requires the full candidate fingerprint before enabling a pin", () => {
    const onPin = vi.fn();
    const { container } = renderPanel({}, { callbacks: { onPin } });

    const pinButton = Array.from(container.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Pin confirmed key"),
    );
    expect(pinButton).toBeInstanceOf(HTMLButtonElement);
    expect(pinButton?.disabled).toBe(true);

    const { container: confirmedContainer } = renderPanel(
      { confirmedFingerprint: CANDIDATE_FINGERPRINT },
      { callbacks: { onPin } },
    );
    const confirmedButton = Array.from(confirmedContainer.querySelectorAll("button")).find(
      (button) => button.textContent?.includes("Pin confirmed key"),
    );
    expect(confirmedButton?.disabled).toBe(false);
    confirmedButton?.click();
    expect(onPin).toHaveBeenCalledOnce();
  });

  it("blocks a rotation whose predecessor does not match the pinned key", () => {
    const { container } = renderPanel({
      discovery: {
        peerPubkey: "f".repeat(64),
        pinnedFingerprint: PINNED_FINGERPRINT,
        trustState: "rotation-chain-mismatch",
        announcement: {
          eventId: "event-id",
          pubkey: "f".repeat(64),
          createdAt: 1_800_000_000,
          publicKey: "base64-key",
          fingerprint: CANDIDATE_FINGERPRINT,
          previousFingerprint: `sha256:${"c".repeat(64)}`,
        },
        relaysQueried: ["wss://relay.example"],
        sourceRelays: ["wss://relay.example"],
      },
    });

    expect(container.textContent).toContain("Rotation blocked");
    expect(container.querySelector("#nostr-pqc-confirmed-fingerprint")).toBeNull();
    expect(container.textContent).not.toContain("Confirm rotation");
  });

  it("keeps mutation controls disabled without operator.admin", () => {
    const { container } = renderPanel(
      { confirmedFingerprint: CANDIDATE_FINGERPRINT },
      { canAdmin: false },
    );
    const publishButton = Array.from(container.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Publish local key"),
    );
    const pinButton = Array.from(container.querySelectorAll("button")).find((button) =>
      button.textContent?.includes("Pin confirmed key"),
    );

    expect(publishButton?.disabled).toBe(true);
    expect(pinButton?.disabled).toBe(true);
  });

  it("renders the complete local fingerprint after publication", () => {
    const localFingerprint = `sha256:${"d".repeat(64)}`;
    const { container } = renderPanel({ publishedFingerprint: localFingerprint });

    expect(container.textContent).toContain("Local fingerprint for out-of-band verification");
    expect(container.textContent).toContain(localFingerprint);
  });
});
