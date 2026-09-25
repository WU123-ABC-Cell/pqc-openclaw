import type { NostrProfile } from "../../api/types.ts";
import { t } from "../../i18n/index.ts";
import { importNostrProfile, parseValidationErrors, putNostrProfile } from "./nostr-profile-ops.ts";
import {
  createNostrProfileFormState,
  type NostrProfileFormState,
} from "./view.nostr-profile-form.ts";

type NostrProfileOperation = {
  accountId: string;
  headers: Record<string, string>;
  isCurrent: () => boolean;
};

type NostrProfileControllerOptions = {
  beginOperation: () => NostrProfileOperation | null;
  invalidateOperations: () => void;
  requestUpdate: () => void;
  refreshChannels: () => Promise<unknown>;
};

function formatOperationError(error: unknown, prefix: string): string {
  return error instanceof DOMException && error.name === "TimeoutError"
    ? t("channels.nostr.notices.timeout")
    : t("channels.nostr.notices.operationFailed", { prefix, error: String(error) });
}

export class NostrProfileController {
  private formStateValue: NostrProfileFormState | null = null;
  private accountIdValue: string | null = null;

  constructor(private readonly options: NostrProfileControllerOptions) {}

  get formState(): NostrProfileFormState | null {
    return this.formStateValue;
  }

  get accountId(): string | null {
    return this.accountIdValue;
  }

  clear(): void {
    this.formStateValue = null;
    this.accountIdValue = null;
    this.options.requestUpdate();
  }

  edit(accountId: string, profile: NostrProfile | null): void {
    this.options.invalidateOperations();
    this.accountIdValue = accountId;
    this.formStateValue = createNostrProfileFormState(profile ?? undefined);
    this.options.requestUpdate();
  }

  cancel(): void {
    this.options.invalidateOperations();
    this.clear();
  }

  changeField(field: keyof NostrProfile, value: string): void {
    const form = this.formStateValue;
    if (!form) {
      return;
    }
    this.update({
      ...form,
      values: { ...form.values, [field]: value },
      fieldErrors: { ...form.fieldErrors, [field]: "" },
    });
  }

  toggleAdvanced(): void {
    const form = this.formStateValue;
    if (form) {
      this.update({ ...form, showAdvanced: !form.showAdvanced });
    }
  }

  async save(): Promise<void> {
    const form = this.formStateValue;
    if (!form || form.saving || form.importing) {
      return;
    }
    const accountId = this.accountIdValue;
    const operation = this.options.beginOperation();
    if (!operation) {
      return;
    }
    this.update({ ...form, saving: true, error: null, success: null, fieldErrors: {} });

    try {
      const { data, response } = await putNostrProfile({
        accountId: operation.accountId,
        headers: operation.headers,
        values: form.values,
      });
      const current = this.current(operation, accountId);
      if (!current) {
        return;
      }
      if (!response.ok || data?.ok === false || !data) {
        this.update({
          ...current,
          saving: false,
          error:
            data?.error ??
            t("channels.nostr.notices.updateFailedStatus", { status: String(response.status) }),
          success: null,
          fieldErrors: parseValidationErrors(data?.details),
        });
        return;
      }
      if (!data.persisted) {
        this.update({
          ...current,
          saving: false,
          error: t("channels.nostr.notices.publishFailed"),
          success: null,
        });
        return;
      }
      this.update({
        ...current,
        saving: false,
        error: null,
        success: t("channels.nostr.notices.published"),
        fieldErrors: {},
        original: { ...form.values },
      });
      await this.options.refreshChannels();
    } catch (error) {
      const current = this.current(operation, accountId);
      if (current) {
        this.update({
          ...current,
          saving: false,
          error: formatOperationError(error, t("channels.nostr.notices.updateFailed")),
          success: null,
        });
      }
    }
  }

  async import(): Promise<void> {
    const form = this.formStateValue;
    if (!form || form.importing || form.saving) {
      return;
    }
    const accountId = this.accountIdValue;
    const operation = this.options.beginOperation();
    if (!operation) {
      return;
    }
    this.update({ ...form, importing: true, error: null, success: null });

    try {
      const { data, response } = await importNostrProfile({
        accountId: operation.accountId,
        headers: operation.headers,
      });
      const current = this.current(operation, accountId);
      if (!current) {
        return;
      }
      if (!response.ok || data?.ok === false || !data) {
        this.update({
          ...current,
          importing: false,
          error:
            data?.error ??
            t("channels.nostr.notices.importFailedStatus", { status: String(response.status) }),
          success: null,
        });
        return;
      }
      const merged = data.merged ?? data.imported ?? null;
      const values = merged ? { ...current.values, ...merged } : current.values;
      this.update({
        ...current,
        importing: false,
        values,
        error: null,
        success: data.saved
          ? t("channels.nostr.notices.importedFromRelays")
          : t("channels.nostr.notices.imported"),
        showAdvanced: Boolean(values.banner || values.website || values.nip05 || values.lud16),
      });
      if (data.saved) {
        await this.options.refreshChannels();
      }
    } catch (error) {
      const current = this.current(operation, accountId);
      if (current) {
        this.update({
          ...current,
          importing: false,
          error: formatOperationError(error, t("channels.nostr.notices.importFailed")),
          success: null,
        });
      }
    }
  }

  private current(
    operation: NostrProfileOperation,
    accountId: string | null,
  ): NostrProfileFormState | null {
    return operation.isCurrent() && this.accountIdValue === accountId ? this.formStateValue : null;
  }

  private update(next: NostrProfileFormState): void {
    this.formStateValue = next;
    this.options.requestUpdate();
  }
}
