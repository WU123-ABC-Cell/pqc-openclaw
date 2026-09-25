import { generateSecretKey, type Event, type SimplePool } from "nostr-tools";
import { openClawPqcDm } from "openclaw/plugin-sdk/security-runtime";
import { describe, expect, it, vi } from "vitest";
import {
  createNostrPqcKeyAnnouncementEvent,
  discoverNostrPqcKeyAnnouncement,
  fingerprintMlKemPublicKey,
  OPENCLAW_PQC_KEY_EVENT_D_TAG,
  OPENCLAW_PQC_KEY_EVENT_KIND,
  parseNostrPqcKeyAnnouncement,
} from "./nostr-pqc-key-announcement.js";

function createMlKemPublicKey(): string {
  const pair = openClawPqcDm.generateMlKem768KeyPair();
  try {
    return openClawPqcDm.encodeMlKemKey(pair.publicKey);
  } finally {
    pair.publicKey.fill(0);
    pair.secretKey.fill(0);
  }
}

describe("Nostr PQC key announcements", () => {
  it("creates and verifies a signed ML-KEM announcement", () => {
    const event = createNostrPqcKeyAnnouncementEvent({
      secretKey: generateSecretKey(),
      publicKey: createMlKemPublicKey(),
      createdAt: 123,
    });

    const parsed = parseNostrPqcKeyAnnouncement(event);
    expect(event.kind).toBe(OPENCLAW_PQC_KEY_EVENT_KIND);
    expect(event.tags).toContainEqual(["d", OPENCLAW_PQC_KEY_EVENT_D_TAG]);
    expect(parsed).toMatchObject({ eventId: event.id, createdAt: 123 });
    expect(parsed?.fingerprint).toBe(fingerprintMlKemPublicKey(parsed?.publicKey ?? ""));
  });

  it("binds a rotation announcement to the prior pinned fingerprint", () => {
    const previousFingerprint = fingerprintMlKemPublicKey(createMlKemPublicKey());
    const event = createNostrPqcKeyAnnouncementEvent({
      secretKey: generateSecretKey(),
      publicKey: createMlKemPublicKey(),
      previousFingerprint,
    });

    expect(parseNostrPqcKeyAnnouncement(event)?.previousFingerprint).toBe(previousFingerprint);
  });

  it("rejects tampering, a wrong author, and malformed ML-KEM material", () => {
    const secretKey = generateSecretKey();
    const event = createNostrPqcKeyAnnouncementEvent({
      secretKey,
      publicKey: createMlKemPublicKey(),
    });
    expect(parseNostrPqcKeyAnnouncement(event, "f".repeat(64))).toBeNull();
    const tampered = structuredClone(event);
    tampered.content = `${tampered.content} `;
    expect(parseNostrPqcKeyAnnouncement(tampered)).toBeNull();

    const malformed = createNostrPqcKeyAnnouncementEvent({
      secretKey,
      publicKey: createMlKemPublicKey(),
    });
    const content = JSON.parse(malformed.content) as Record<string, unknown>;
    content.publicKey = "not-a-key";
    const malformedWireEvent = structuredClone(malformed);
    malformedWireEvent.content = JSON.stringify(content);
    expect(parseNostrPqcKeyAnnouncement(malformedWireEvent)).toBeNull();
  });

  it("rejects ambiguous d tags and announcements too far in the future", () => {
    const secretKey = generateSecretKey();
    const publicKey = createMlKemPublicKey();
    const future = createNostrPqcKeyAnnouncementEvent({
      secretKey,
      publicKey,
      createdAt: Math.floor(Date.now() / 1000) + 301,
    });
    expect(parseNostrPqcKeyAnnouncement(future)).toBeNull();

    const event = createNostrPqcKeyAnnouncementEvent({ secretKey, publicKey });
    const ambiguous = structuredClone(event);
    ambiguous.tags.push(["d", OPENCLAW_PQC_KEY_EVENT_D_TAG]);
    expect(parseNostrPqcKeyAnnouncement(ambiguous)).toBeNull();
  });

  it("selects the canonical latest valid addressable event across relays", async () => {
    const secretKey = generateSecretKey();
    const older = createNostrPqcKeyAnnouncementEvent({
      secretKey,
      publicKey: createMlKemPublicKey(),
      createdAt: 100,
    });
    const latestA = createNostrPqcKeyAnnouncementEvent({
      secretKey,
      publicKey: createMlKemPublicKey(),
      createdAt: 200,
    });
    const latestB = createNostrPqcKeyAnnouncementEvent({
      secretKey,
      publicKey: createMlKemPublicKey(),
      createdAt: 200,
    });
    const winner = latestA.id < latestB.id ? latestA : latestB;
    const perRelay = new Map<string, Event>([
      ["wss://one.example", older],
      ["wss://two.example", latestA],
      ["wss://three.example", latestB],
    ]);
    const close = vi.fn();
    const pool = {
      subscribeMany(
        relays: string[],
        _filter: unknown,
        handlers: { onevent: (event: Event) => void; oneose: () => void },
      ) {
        queueMicrotask(() => {
          const event = perRelay.get(relays[0] ?? "");
          if (event) {
            handlers.onevent(event);
          }
          handlers.oneose();
        });
        return { close };
      },
    } as unknown as SimplePool;

    const result = await discoverNostrPqcKeyAnnouncement({
      pubkey: older.pubkey,
      relays: [...perRelay.keys()],
      pool,
    });

    expect(result.announcement?.eventId).toBe(winner.id);
    expect(result.sourceRelays).toHaveLength(1);
    expect(close).toHaveBeenCalledTimes(3);
  });
});
