import { createHash } from "node:crypto";
import { finalizeEvent, SimplePool, verifyEvent, type Event } from "nostr-tools";
import { formatErrorMessage } from "openclaw/plugin-sdk/error-runtime";
import { openClawPqcDm } from "openclaw/plugin-sdk/security-runtime";
import { publishNostrEventToRelay } from "./relay-publish.js";

export const OPENCLAW_PQC_KEY_EVENT_KIND = 30078;
export const OPENCLAW_PQC_KEY_EVENT_D_TAG = "openclaw-pqc-dm-key-v1";
const OPENCLAW_PQC_KEY_VERSION = 1;
const OPENCLAW_PQC_KEY_ALGORITHM = "ML-KEM-768";
const DEFAULT_DISCOVERY_TIMEOUT_MS = 5_000;
const MAX_ANNOUNCEMENT_CONTENT_BYTES = 4 * 1024;
const MAX_FUTURE_SKEW_SEC = 5 * 60;
const FINGERPRINT_PATTERN = /^sha256:[0-9a-f]{64}$/u;

export type NostrPqcKeyAnnouncement = {
  eventId: string;
  pubkey: string;
  createdAt: number;
  publicKey: string;
  fingerprint: string;
  previousFingerprint?: string;
};

export type NostrPqcKeyPublishResult = NostrPqcKeyAnnouncement & {
  successes: string[];
  failures: Array<{ relay: string; error: string }>;
};

type AnnouncementContent = {
  version: 1;
  algorithm: "ML-KEM-768";
  publicKey: string;
  fingerprint: string;
  previousFingerprint?: string;
};

export function fingerprintMlKemPublicKey(encodedPublicKey: string): string {
  const publicKey = openClawPqcDm.decodeMlKem768PublicKey(encodedPublicKey);
  try {
    return `sha256:${createHash("sha256").update(publicKey).digest("hex")}`;
  } finally {
    publicKey.fill(0);
  }
}

function hasAnnouncementDTag(event: Pick<Event, "tags">): boolean {
  const dTags = event.tags.filter((tag) => tag[0] === "d");
  return dTags.length === 1 && dTags[0]?.[1] === OPENCLAW_PQC_KEY_EVENT_D_TAG;
}

export function createNostrPqcKeyAnnouncementEvent(params: {
  secretKey: Uint8Array;
  publicKey: string;
  previousFingerprint?: string;
  createdAt?: number;
}): Event {
  const fingerprint = fingerprintMlKemPublicKey(params.publicKey);
  const content: AnnouncementContent = {
    version: OPENCLAW_PQC_KEY_VERSION,
    algorithm: OPENCLAW_PQC_KEY_ALGORITHM,
    publicKey: params.publicKey,
    fingerprint,
    ...(params.previousFingerprint ? { previousFingerprint: params.previousFingerprint } : {}),
  };
  return finalizeEvent(
    {
      kind: OPENCLAW_PQC_KEY_EVENT_KIND,
      created_at: params.createdAt ?? Math.floor(Date.now() / 1000),
      tags: [["d", OPENCLAW_PQC_KEY_EVENT_D_TAG]],
      content: JSON.stringify(content),
    },
    params.secretKey,
  );
}

export function parseNostrPqcKeyAnnouncement(
  event: Event,
  expectedPubkey?: string,
): NostrPqcKeyAnnouncement | null {
  if (
    event.kind !== OPENCLAW_PQC_KEY_EVENT_KIND ||
    !hasAnnouncementDTag(event) ||
    event.created_at > Math.floor(Date.now() / 1000) + MAX_FUTURE_SKEW_SEC ||
    Buffer.byteLength(event.content, "utf8") > MAX_ANNOUNCEMENT_CONTENT_BYTES ||
    (expectedPubkey !== undefined && event.pubkey !== expectedPubkey) ||
    !verifyEvent(event)
  ) {
    return null;
  }

  let content: unknown;
  try {
    content = JSON.parse(event.content) as unknown;
  } catch {
    return null;
  }
  if (typeof content !== "object" || content === null || Array.isArray(content)) {
    return null;
  }
  const candidate = content as Partial<AnnouncementContent>;
  if (
    candidate.version !== OPENCLAW_PQC_KEY_VERSION ||
    candidate.algorithm !== OPENCLAW_PQC_KEY_ALGORITHM ||
    typeof candidate.publicKey !== "string" ||
    typeof candidate.fingerprint !== "string" ||
    (candidate.previousFingerprint !== undefined &&
      (typeof candidate.previousFingerprint !== "string" ||
        !FINGERPRINT_PATTERN.test(candidate.previousFingerprint)))
  ) {
    return null;
  }

  let computedFingerprint: string;
  try {
    computedFingerprint = fingerprintMlKemPublicKey(candidate.publicKey);
  } catch {
    return null;
  }
  if (computedFingerprint !== candidate.fingerprint) {
    return null;
  }

  return {
    eventId: event.id,
    pubkey: event.pubkey,
    createdAt: event.created_at,
    publicKey: candidate.publicKey,
    fingerprint: computedFingerprint,
    ...(candidate.previousFingerprint
      ? { previousFingerprint: candidate.previousFingerprint }
      : {}),
  };
}

export async function publishNostrPqcKeyAnnouncement(params: {
  pool: SimplePool;
  secretKey: Uint8Array;
  publicKey: string;
  relays: string[];
  previousFingerprint?: string;
  createdAt?: number;
}): Promise<NostrPqcKeyPublishResult> {
  const event = createNostrPqcKeyAnnouncementEvent(params);
  const announcement = parseNostrPqcKeyAnnouncement(event);
  if (!announcement) {
    throw new Error("Failed to create a valid OpenClaw PQC key announcement");
  }
  const successes: string[] = [];
  const failures: Array<{ relay: string; error: string }> = [];
  await Promise.all(
    params.relays.map(async (relay) => {
      try {
        await publishNostrEventToRelay(params.pool, relay, event);
        successes.push(relay);
      } catch (error) {
        failures.push({ relay, error: formatErrorMessage(error) });
      }
    }),
  );
  return { ...announcement, successes, failures };
}

export async function discoverNostrPqcKeyAnnouncement(params: {
  pubkey: string;
  relays: string[];
  timeoutMs?: number;
  pool?: SimplePool;
}): Promise<{
  announcement: NostrPqcKeyAnnouncement | null;
  relaysQueried: string[];
  sourceRelays: string[];
}> {
  const pool = params.pool ?? new SimplePool();
  const ownsPool = params.pool === undefined;
  const timeoutMs = params.timeoutMs ?? DEFAULT_DISCOVERY_TIMEOUT_MS;
  const subscriptions: Array<ReturnType<SimplePool["subscribeMany"]>> = [];
  const events: Array<{ event: Event; relay: string }> = [];
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    await Promise.race([
      Promise.all(
        params.relays.map(
          (relay) =>
            new Promise<void>((resolve) => {
              const subscription = pool.subscribeMany(
                [relay],
                {
                  kinds: [OPENCLAW_PQC_KEY_EVENT_KIND],
                  authors: [params.pubkey],
                  "#d": [OPENCLAW_PQC_KEY_EVENT_D_TAG],
                  limit: 1,
                },
                {
                  onevent(event) {
                    events.push({ event, relay });
                  },
                  oneose() {
                    resolve();
                  },
                  onclose() {
                    resolve();
                  },
                },
              );
              subscriptions.push(subscription);
            }),
        ),
      ),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
    for (const subscription of subscriptions) {
      subscription.close();
    }
    if (ownsPool) {
      pool.close(params.relays);
    }
  }

  const valid = events
    .map(({ event, relay }) => ({
      announcement: parseNostrPqcKeyAnnouncement(event, params.pubkey),
      relay,
    }))
    .filter(
      (item): item is { announcement: NostrPqcKeyAnnouncement; relay: string } =>
        item.announcement !== null,
    );
  if (valid.length === 0) {
    return { announcement: null, relaysQueried: [...params.relays], sourceRelays: [] };
  }
  const best = valid.reduce((current, candidate) => {
    if (candidate.announcement.createdAt !== current.announcement.createdAt) {
      return candidate.announcement.createdAt > current.announcement.createdAt
        ? candidate
        : current;
    }
    return candidate.announcement.eventId < current.announcement.eventId ? candidate : current;
  });
  return {
    announcement: best.announcement,
    relaysQueried: [...params.relays],
    sourceRelays: valid
      .filter((item) => item.announcement.eventId === best.announcement.eventId)
      .map((item) => item.relay),
  };
}
