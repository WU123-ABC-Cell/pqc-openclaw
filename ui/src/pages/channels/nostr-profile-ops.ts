// Nostr HTTP operations for the channels page: gateway REST calls for profile
// management and the operator-confirmed PQC peer-key trust workflow.
import type { NostrProfile } from "../../api/types.ts";

const NOSTR_REQUEST_TIMEOUT_MS = 30_000;

type NostrHttpResult<T> = {
  data: T | null;
  response: Response;
};

async function requestNostr<T>(
  url: string,
  init: Omit<RequestInit, "signal">,
): Promise<NostrHttpResult<T>> {
  const controller = new AbortController();
  const timeout = setTimeout(
    () =>
      controller.abort(
        new DOMException("Nostr request timed out after 30 seconds", "TimeoutError"),
      ),
    NOSTR_REQUEST_TIMEOUT_MS,
  );
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    let data: T | null = null;
    try {
      data = (await response.json()) as T;
    } catch (error) {
      if (controller.signal.aborted) {
        throw controller.signal.reason ?? error;
      }
    }
    return { data, response };
  } finally {
    clearTimeout(timeout);
  }
}

export function parseValidationErrors(details: unknown): Record<string, string> {
  if (!Array.isArray(details)) {
    return {};
  }
  const errors: Record<string, string> = {};
  for (const entry of details) {
    if (typeof entry !== "string") {
      continue;
    }
    const [rawField, ...rest] = entry.split(":");
    if (!rawField || rest.length === 0) {
      continue;
    }
    const field = rawField.trim();
    const message = rest.join(":").trim();
    if (field && message) {
      errors[field] = message;
    }
  }
  return errors;
}

function buildNostrProfileUrl(accountId: string, suffix = ""): string {
  return `/api/channels/nostr/${encodeURIComponent(accountId)}/profile${suffix}`;
}

function buildNostrPqcKeyUrl(accountId: string, suffix: string): string {
  return `/api/channels/nostr/${encodeURIComponent(accountId)}/pqc-keys/${suffix}`;
}

export async function putNostrProfile(params: {
  accountId: string;
  headers: Record<string, string>;
  values: NostrProfile;
}) {
  return await requestNostr<{
    ok?: boolean;
    error?: string;
    details?: unknown;
    persisted?: boolean;
  }>(buildNostrProfileUrl(params.accountId), {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      ...params.headers,
    },
    body: JSON.stringify(params.values),
  });
}

export async function importNostrProfile(params: {
  accountId: string;
  headers: Record<string, string>;
}) {
  return await requestNostr<{
    ok?: boolean;
    error?: string;
    imported?: NostrProfile;
    merged?: NostrProfile;
    saved?: boolean;
  }>(buildNostrProfileUrl(params.accountId, "/import"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...params.headers,
    },
    body: JSON.stringify({ autoMerge: true }),
  });
}

export type NostrPqcTrustState =
  | "not-found"
  | "pinned"
  | "untrusted-first-key"
  | "untrusted-rotation"
  | "rotation-chain-mismatch";

export type NostrPqcKeyAnnouncement = {
  eventId: string;
  pubkey: string;
  createdAt: number;
  publicKey: string;
  fingerprint: string;
  previousFingerprint?: string;
};

export type NostrPqcKeyDiscovery = {
  peerPubkey: string;
  pinnedFingerprint: string | null;
  trustState: NostrPqcTrustState;
  announcement: NostrPqcKeyAnnouncement | null;
  relaysQueried: string[];
  sourceRelays: string[];
};

type NostrPqcErrorResponse = {
  ok?: false;
  error?: string;
};

export async function discoverNostrPqcKey(params: {
  accountId: string;
  peerPubkey: string;
  headers: Record<string, string>;
}) {
  return await requestNostr<(NostrPqcKeyDiscovery & { ok: true }) | NostrPqcErrorResponse>(
    buildNostrPqcKeyUrl(params.accountId, encodeURIComponent(params.peerPubkey)),
    {
      method: "GET",
      headers: params.headers,
    },
  );
}

export async function pinNostrPqcKey(params: {
  accountId: string;
  peerPubkey: string;
  fingerprint: string;
  expectedCurrentFingerprint: string | null;
  headers: Record<string, string>;
}) {
  return await requestNostr<
    | {
        ok: true;
        updated: boolean;
        announcement: NostrPqcKeyAnnouncement;
      }
    | NostrPqcErrorResponse
  >(buildNostrPqcKeyUrl(params.accountId, encodeURIComponent(params.peerPubkey)), {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      ...params.headers,
    },
    body: JSON.stringify({
      fingerprint: params.fingerprint,
      expectedCurrentFingerprint: params.expectedCurrentFingerprint,
    }),
  });
}

export async function publishNostrPqcKey(params: {
  accountId: string;
  headers: Record<string, string>;
}) {
  return await requestNostr<
    | (NostrPqcKeyAnnouncement & {
        ok: true;
        successes: string[];
        failures: Array<{ relay: string; error: string }>;
      })
    | NostrPqcErrorResponse
  >(buildNostrPqcKeyUrl(params.accountId, "publish"), {
    method: "POST",
    headers: params.headers,
  });
}
