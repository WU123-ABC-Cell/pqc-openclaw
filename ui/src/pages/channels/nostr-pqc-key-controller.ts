import { t } from "../../i18n/index.ts";
import { discoverNostrPqcKey, pinNostrPqcKey, publishNostrPqcKey } from "./nostr-profile-ops.ts";
import { createNostrPqcKeyPanelState, type NostrPqcKeyPanelState } from "./view.nostr-pqc-keys.ts";

type NostrPqcOperation = {
  accountId: string;
  headers: Record<string, string>;
  isCurrent: () => boolean;
};

type NostrPqcKeyControllerOptions = {
  beginOperation: () => NostrPqcOperation | null;
  invalidateOperations: () => void;
  requestUpdate: () => void;
};

function formatOperationError(error: unknown, prefix: string): string {
  return error instanceof DOMException && error.name === "TimeoutError"
    ? t("channels.nostr.notices.timeout")
    : t("channels.nostr.notices.operationFailed", { prefix, error: String(error) });
}

function readOperationError(data: unknown): string | null {
  if (typeof data !== "object" || data === null || !("error" in data)) {
    return null;
  }
  return typeof data.error === "string" ? data.error : null;
}

export class NostrPqcKeyController {
  private stateValue = createNostrPqcKeyPanelState();

  constructor(private readonly options: NostrPqcKeyControllerOptions) {}

  get state(): NostrPqcKeyPanelState {
    return this.stateValue;
  }

  clear(): void {
    this.update(createNostrPqcKeyPanelState());
  }

  setPeerPubkey(value: string): void {
    this.options.invalidateOperations();
    this.update({
      ...createNostrPqcKeyPanelState(),
      publishedFingerprint: this.stateValue.publishedFingerprint,
      peerPubkey: value,
    });
  }

  setConfirmedFingerprint(value: string): void {
    this.update({
      ...this.stateValue,
      confirmedFingerprint: value,
      error: null,
    });
  }

  async discover(): Promise<void> {
    const peerPubkey = this.stateValue.peerPubkey.trim();
    if (!peerPubkey || this.stateValue.discovering) {
      return;
    }
    if (peerPubkey !== this.stateValue.peerPubkey) {
      this.update({ ...this.stateValue, peerPubkey });
    }
    const operation = this.options.beginOperation();
    if (!operation) {
      return;
    }
    this.update({
      ...this.stateValue,
      discovering: true,
      discovery: null,
      confirmedFingerprint: "",
      error: null,
      notice: null,
    });

    try {
      const { data, response } = await discoverNostrPqcKey({
        accountId: operation.accountId,
        peerPubkey,
        headers: operation.headers,
      });
      const current = this.current(operation, peerPubkey);
      if (!current) {
        return;
      }
      if (!response.ok || !data || data.ok !== true || !("trustState" in data)) {
        this.update({
          ...current,
          discovering: false,
          error:
            readOperationError(data) ??
            t("channels.nostr.pqcKeys.requestFailedStatus", {
              status: String(response.status),
            }),
        });
        return;
      }
      const { ok: _ok, ...discovery } = data;
      this.update({ ...current, discovering: false, discovery });
    } catch (error) {
      const current = this.current(operation, peerPubkey);
      if (!current) {
        return;
      }
      this.update({
        ...current,
        discovering: false,
        error: formatOperationError(error, t("channels.nostr.pqcKeys.discoveryFailed")),
      });
    }
  }

  async pin(): Promise<void> {
    const panelState = this.stateValue;
    const candidate = panelState.discovery?.announcement;
    const canPin =
      panelState.discovery?.trustState === "untrusted-first-key" ||
      panelState.discovery?.trustState === "untrusted-rotation";
    if (
      panelState.pinning ||
      !candidate ||
      !canPin ||
      panelState.confirmedFingerprint.trim() !== candidate.fingerprint
    ) {
      return;
    }
    const peerPubkey = panelState.peerPubkey;
    const operation = this.options.beginOperation();
    if (!operation) {
      return;
    }
    this.update({ ...panelState, pinning: true, error: null, notice: null });

    try {
      const { data, response } = await pinNostrPqcKey({
        accountId: operation.accountId,
        peerPubkey: peerPubkey.trim(),
        fingerprint: candidate.fingerprint,
        expectedCurrentFingerprint: panelState.discovery?.pinnedFingerprint ?? null,
        headers: operation.headers,
      });
      const current = this.current(operation, peerPubkey);
      if (!current) {
        return;
      }
      if (!response.ok || !data || data.ok !== true || !("announcement" in data)) {
        this.update({
          ...current,
          pinning: false,
          error:
            readOperationError(data) ??
            t("channels.nostr.pqcKeys.requestFailedStatus", {
              status: String(response.status),
            }),
        });
        return;
      }
      this.update({
        ...current,
        pinning: false,
        confirmedFingerprint: "",
        discovery: current.discovery
          ? {
              ...current.discovery,
              pinnedFingerprint: data.announcement.fingerprint,
              trustState: "pinned",
              announcement: data.announcement,
            }
          : null,
        notice: data.updated
          ? t("channels.nostr.pqcKeys.pinned")
          : t("channels.nostr.pqcKeys.alreadyPinned"),
      });
    } catch (error) {
      const current = this.current(operation, peerPubkey);
      if (!current) {
        return;
      }
      this.update({
        ...current,
        pinning: false,
        error: formatOperationError(error, t("channels.nostr.pqcKeys.pinFailed")),
      });
    }
  }

  async publish(): Promise<void> {
    if (this.stateValue.publishing) {
      return;
    }
    const peerPubkey = this.stateValue.peerPubkey;
    const operation = this.options.beginOperation();
    if (!operation) {
      return;
    }
    this.update({ ...this.stateValue, publishing: true, error: null, notice: null });

    try {
      const { data, response } = await publishNostrPqcKey({
        accountId: operation.accountId,
        headers: operation.headers,
      });
      const current = this.current(operation, peerPubkey);
      if (!current) {
        return;
      }
      if (!response.ok || !data || data.ok !== true || !("successes" in data)) {
        this.update({
          ...current,
          publishing: false,
          error:
            readOperationError(data) ??
            t("channels.nostr.pqcKeys.requestFailedStatus", {
              status: String(response.status),
            }),
        });
        return;
      }
      this.update({
        ...current,
        publishing: false,
        publishedFingerprint: data.fingerprint,
        notice: t("channels.nostr.pqcKeys.published", {
          successes: String(data.successes.length),
          failures: String(data.failures.length),
        }),
      });
    } catch (error) {
      const current = this.current(operation, peerPubkey);
      if (!current) {
        return;
      }
      this.update({
        ...current,
        publishing: false,
        error: formatOperationError(error, t("channels.nostr.pqcKeys.publishFailed")),
      });
    }
  }

  private current(operation: NostrPqcOperation, peerPubkey: string): NostrPqcKeyPanelState | null {
    return operation.isCurrent() && this.stateValue.peerPubkey === peerPubkey
      ? this.stateValue
      : null;
  }

  private update(next: NostrPqcKeyPanelState): void {
    this.stateValue = next;
    this.options.requestUpdate();
  }
}
