import fs from "node:fs/promises";
// Nostr E2E tests exercise two real buses through an ephemeral local relay.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  verifyEvent,
  type Event,
  type Filter,
} from "nostr-tools";
import { encrypt as encryptLegacyNip04 } from "nostr-tools/nip04";
import {
  closeOpenClawStateDatabaseForTest,
  createChannelIngressQueueForTests,
} from "openclaw/plugin-sdk/plugin-state-test-runtime";
import { openClawPqcDm } from "openclaw/plugin-sdk/security-runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import WebSocket, { WebSocketServer, type RawData } from "ws";
import type { PluginRuntime } from "../runtime-api.js";
import { startNostrBus, type NostrBusHandle } from "./nostr-bus.js";
import { setNostrRuntime } from "./runtime.js";

type PersistedBusState = {
  version: 2;
  lastProcessedAt: number | null;
  gatewayStartedAt: number | null;
  recentEventIds: string[];
};

type PersistedPqcKeyState = {
  version: 1;
  lastPublishedAt: number;
  lastPublishedEventId: string;
  fingerprint: string;
};

const stateMocks = vi.hoisted(() => ({
  states: new Map<string, PersistedBusState>(),
  pqcKeyStates: new Map<string, PersistedPqcKeyState>(),
}));

vi.mock("./nostr-state-store.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./nostr-state-store.js")>();
  return {
    ...actual,
    readNostrBusState: vi.fn(async ({ accountId }: { accountId: string }) => {
      return stateMocks.states.get(accountId) ?? null;
    }),
    writeNostrBusState: vi.fn(
      async ({
        accountId,
        lastProcessedAt,
        gatewayStartedAt,
        recentEventIds,
      }: {
        accountId: string;
        lastProcessedAt: number;
        gatewayStartedAt: number;
        recentEventIds: string[];
      }) => {
        stateMocks.states.set(accountId, {
          version: 2,
          lastProcessedAt,
          gatewayStartedAt,
          recentEventIds,
        });
      },
    ),
    readNostrProfileState: vi.fn(async () => null),
    writeNostrProfileState: vi.fn(async () => {}),
    readNostrPqcKeyState: vi.fn(async ({ accountId }: { accountId: string }) => {
      return stateMocks.pqcKeyStates.get(accountId) ?? null;
    }),
    writeNostrPqcKeyState: vi.fn(
      async ({
        accountId,
        lastPublishedAt,
        lastPublishedEventId,
        fingerprint,
      }: {
        accountId: string;
        lastPublishedAt: number;
        lastPublishedEventId: string;
        fingerprint: string;
      }) => {
        stateMocks.pqcKeyStates.set(accountId, {
          version: 1,
          lastPublishedAt,
          lastPublishedEventId,
          fingerprint,
        });
      },
    ),
  };
});

type RelaySubscription = {
  socket: WebSocket;
  id: string;
  filters: Filter[];
};

function eventMatchesFilter(event: Event, filter: Filter): boolean {
  if (filter.ids && !filter.ids.some((id) => event.id.startsWith(id))) {
    return false;
  }
  if (filter.authors && !filter.authors.some((author) => event.pubkey.startsWith(author))) {
    return false;
  }
  if (filter.kinds && !filter.kinds.includes(event.kind)) {
    return false;
  }
  if (filter.since !== undefined && event.created_at < filter.since) {
    return false;
  }
  if (filter.until !== undefined && event.created_at > filter.until) {
    return false;
  }
  for (const [key, values] of Object.entries(filter)) {
    if (!key.startsWith("#") || !Array.isArray(values)) {
      continue;
    }
    const tagName = key.slice(1);
    const tagValues = values as string[];
    if (!event.tags.some((tag) => tag[0] === tagName && tagValues.includes(tag[1] ?? ""))) {
      return false;
    }
  }
  return true;
}

function eventMatchesAnyFilter(event: Event, filters: Filter[]): boolean {
  return filters.some((filter) => eventMatchesFilter(event, filter));
}

class LocalNostrRelay {
  private readonly server: Server;
  private readonly webSocketServer: WebSocketServer;
  private readonly subscriptions = new Set<RelaySubscription>();
  readonly events: Event[] = [];
  readonly requestedFilters: Filter[][] = [];
  readonly url: string;

  private constructor(server: Server, webSocketServer: WebSocketServer, url: string) {
    this.server = server;
    this.webSocketServer = webSocketServer;
    this.url = url;

    webSocketServer.on("connection", (socket) => {
      socket.on("message", (data) => this.handleMessage(socket, data));
      socket.on("close", () => {
        for (const subscription of this.subscriptions) {
          if (subscription.socket === socket) {
            this.subscriptions.delete(subscription);
          }
        }
      });
    });
  }

  static async start(): Promise<LocalNostrRelay> {
    const server = createServer();
    const webSocketServer = new WebSocketServer({ server });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address() as AddressInfo;
    return new LocalNostrRelay(server, webSocketServer, `ws://127.0.0.1:${address.port}`);
  }

  subscriptionCount(): number {
    return this.subscriptions.size;
  }

  broadcastIgnoringFilters(event: Event): void {
    for (const subscription of this.subscriptions) {
      this.send(subscription.socket, ["EVENT", subscription.id, event]);
    }
  }

  async close(): Promise<void> {
    for (const socket of this.webSocketServer.clients) {
      socket.terminate();
    }
    await new Promise<void>((resolve) => {
      this.webSocketServer.close(() => resolve());
    });
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  private handleMessage(socket: WebSocket, data: RawData): void {
    let message: unknown;
    try {
      let text: string;
      if (Array.isArray(data)) {
        text = Buffer.concat(data).toString("utf8");
      } else if (data instanceof ArrayBuffer) {
        text = Buffer.from(new Uint8Array(data)).toString("utf8");
      } else {
        text = data.toString("utf8");
      }
      message = JSON.parse(text);
    } catch {
      return;
    }
    if (!Array.isArray(message) || typeof message[0] !== "string") {
      return;
    }

    if (message[0] === "REQ" && typeof message[1] === "string") {
      const filters = message.slice(2).filter((value): value is Filter => {
        return typeof value === "object" && value !== null;
      });
      const subscription = { socket, id: message[1], filters };
      this.subscriptions.add(subscription);
      this.requestedFilters.push(filters);
      for (const event of this.events) {
        if (eventMatchesAnyFilter(event, filters)) {
          this.send(socket, ["EVENT", subscription.id, event]);
        }
      }
      this.send(socket, ["EOSE", subscription.id]);
      return;
    }

    if (message[0] === "CLOSE" && typeof message[1] === "string") {
      for (const subscription of this.subscriptions) {
        if (subscription.socket === socket && subscription.id === message[1]) {
          this.subscriptions.delete(subscription);
        }
      }
      return;
    }

    if (message[0] !== "EVENT" || typeof message[1] !== "object" || message[1] === null) {
      return;
    }
    const event = message[1] as Event;
    if (!verifyEvent(event)) {
      this.send(socket, ["OK", event.id, false, "invalid: signature"]);
      return;
    }
    this.events.push(event);
    this.send(socket, ["OK", event.id, true, "stored"]);
    for (const subscription of this.subscriptions) {
      if (eventMatchesAnyFilter(event, subscription.filters)) {
        this.send(subscription.socket, ["EVENT", subscription.id, event]);
      }
    }
  }

  private send(socket: WebSocket, message: unknown): void {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(message));
    }
  }
}

type TestIdentity = {
  secretKey: Uint8Array;
  privateKey: string;
  publicKey: string;
  mlKemPublicKey: Uint8Array;
  mlKemSecretKey: Uint8Array;
  encodedMlKemPublicKey: string;
  encodedMlKemSecretKey: string;
};

function createTestIdentity(): TestIdentity {
  const secretKey = generateSecretKey();
  const mlKem = openClawPqcDm.generateMlKem768KeyPair();
  return {
    secretKey,
    privateKey: Buffer.from(secretKey).toString("hex"),
    publicKey: getPublicKey(secretKey),
    mlKemPublicKey: mlKem.publicKey,
    mlKemSecretKey: mlKem.secretKey,
    encodedMlKemPublicKey: openClawPqcDm.encodeMlKemKey(mlKem.publicKey),
    encodedMlKemSecretKey: openClawPqcDm.encodeMlKemKey(mlKem.secretKey),
  };
}

function rotateTestMlKemIdentity(identity: TestIdentity): TestIdentity {
  const mlKem = openClawPqcDm.generateMlKem768KeyPair();
  return {
    secretKey: new Uint8Array(identity.secretKey),
    privateKey: identity.privateKey,
    publicKey: identity.publicKey,
    mlKemPublicKey: mlKem.publicKey,
    mlKemSecretKey: mlKem.secretKey,
    encodedMlKemPublicKey: openClawPqcDm.encodeMlKemKey(mlKem.publicKey),
    encodedMlKemSecretKey: openClawPqcDm.encodeMlKemKey(mlKem.secretKey),
  };
}

function clearTestIdentity(identity: TestIdentity): void {
  identity.secretKey.fill(0);
  identity.mlKemPublicKey.fill(0);
  identity.mlKemSecretKey.fill(0);
}

describe("Nostr PQC two-peer relay E2E", () => {
  let stateDir = "";
  let relay: LocalNostrRelay;
  let alice: TestIdentity;
  let bob: TestIdentity;
  let handles: NostrBusHandle[] = [];

  beforeEach(async () => {
    const created = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-nostr-pqc-e2e-"));
    stateDir = await fs.realpath(created);
    relay = await LocalNostrRelay.start();
    alice = createTestIdentity();
    bob = createTestIdentity();
    handles = [];
    stateMocks.states.clear();
    stateMocks.pqcKeyStates.clear();

    const queues = new Map<string, ReturnType<typeof createChannelIngressQueueForTests>>();
    setNostrRuntime({
      state: {
        openChannelIngressQueue: ({ accountId }: { accountId: string }) => {
          let queue = queues.get(accountId);
          if (!queue) {
            queue = createChannelIngressQueueForTests({
              channelId: "nostr",
              accountId,
              stateDir,
            });
            queues.set(accountId, queue);
          }
          return queue;
        },
      },
    } as unknown as PluginRuntime);
  });

  afterEach(async () => {
    await Promise.allSettled(handles.map((handle) => handle.close()));
    await relay.close();
    closeOpenClawStateDatabaseForTest();
    await fs.rm(stateDir, { recursive: true, force: true });
    clearTestIdentity(alice);
    clearTestIdentity(bob);
  });

  it("delivers bidirectionally, recovers an offline message, and rejects downgrade traffic", async () => {
    const aliceMessages: string[] = [];
    const bobMessages: string[] = [];

    const aliceBus = await startNostrBus({
      accountId: "alice",
      privateKey: alice.privateKey,
      mlKemSecretKey: alice.encodedMlKemSecretKey,
      mlKemPeerPublicKeys: { [bob.publicKey]: bob.encodedMlKemPublicKey },
      relays: [relay.url],
      onMessage: async (_pubkey, text) => {
        aliceMessages.push(text);
      },
    });
    handles.push(aliceBus);

    let bobBus = await startNostrBus({
      accountId: "bob",
      privateKey: bob.privateKey,
      mlKemSecretKey: bob.encodedMlKemSecretKey,
      mlKemPeerPublicKeys: { [alice.publicKey]: alice.encodedMlKemPublicKey },
      relays: [relay.url],
      onMessage: async (_pubkey, text, reply) => {
        bobMessages.push(text);
        if (text === "hello bob") {
          await reply("hello alice");
        }
      },
      onMetric: () => {},
    });
    handles.push(bobBus);

    await vi.waitFor(() => expect(relay.subscriptionCount()).toBe(2));
    expect(
      relay.requestedFilters.flat().every((filter) => {
        return filter.kinds?.length === 1 && filter.kinds[0] === 4444;
      }),
    ).toBe(true);

    const publishResult = await aliceBus.publishPqcKeyAnnouncement();
    expect(publishResult.successes).toEqual([relay.url]);
    const discovery = await bobBus.discoverPeerPqcKey(alice.publicKey);
    expect(discovery.announcement).toMatchObject({
      pubkey: alice.publicKey,
      publicKey: alice.encodedMlKemPublicKey,
      fingerprint: publishResult.fingerprint,
    });
    expect(discovery.sourceRelays).toEqual([relay.url]);

    await aliceBus.sendDm(bob.publicKey, "hello bob");
    await vi.waitFor(() => expect(bobMessages).toEqual(["hello bob"]));
    await vi.waitFor(() => expect(aliceMessages).toEqual(["hello alice"]));
    const dmEvents = relay.events.filter((event) => event.kind === 4444);
    expect(dmEvents).toHaveLength(2);
    expect(dmEvents.every((event) => verifyEvent(event))).toBe(true);
    expect(dmEvents.every((event) => event.content.startsWith("ocpqc1:"))).toBe(true);

    await bobBus.close();
    await vi.waitFor(() => expect(relay.subscriptionCount()).toBe(1));
    await aliceBus.sendDm(bob.publicKey, "queued while offline");

    bobBus = await startNostrBus({
      accountId: "bob",
      privateKey: bob.privateKey,
      mlKemSecretKey: bob.encodedMlKemSecretKey,
      mlKemPeerPublicKeys: { [alice.publicKey]: alice.encodedMlKemPublicKey },
      relays: [relay.url],
      onMessage: async (_pubkey, text) => {
        bobMessages.push(text);
      },
      onMetric: () => {},
    });
    handles.push(bobBus);
    await vi.waitFor(() => expect(bobMessages).toEqual(["hello bob", "queued while offline"]));

    const disguisedLegacyEvent = finalizeEvent(
      {
        kind: 4444,
        tags: [["p", bob.publicKey]],
        content: encryptLegacyNip04(alice.secretKey, bob.publicKey, "legacy downgrade"),
        created_at: Math.floor(Date.now() / 1000),
      },
      alice.secretKey,
    );
    relay.broadcastIgnoringFilters(disguisedLegacyEvent);
    await vi.waitFor(() => {
      const snapshot = bobBus.getMetrics();
      expect(snapshot.eventsRejected.decryptFailed).toBeGreaterThan(0);
    });
    expect(bobMessages).toEqual(["hello bob", "queued while offline"]);
  }, 30_000);

  it("requires explicit pins and applies a confirmed chained rotation to the live sender", async () => {
    const aliceMessages: string[] = [];
    const bobMessages: string[] = [];
    const rotatedBobErrors: Error[] = [];
    let rotatedBob: TestIdentity | undefined;

    try {
      const aliceBus = await startNostrBus({
        accountId: "alice",
        privateKey: alice.privateKey,
        mlKemSecretKey: alice.encodedMlKemSecretKey,
        mlKemPeerPublicKeys: {},
        relays: [relay.url],
        onMessage: async (_pubkey, text) => {
          aliceMessages.push(text);
        },
      });
      handles.push(aliceBus);

      const bobBus = await startNostrBus({
        accountId: "bob",
        privateKey: bob.privateKey,
        mlKemSecretKey: bob.encodedMlKemSecretKey,
        mlKemPeerPublicKeys: {},
        relays: [relay.url],
        onMessage: async (_pubkey, text) => {
          bobMessages.push(text);
        },
      });
      handles.push(bobBus);
      await vi.waitFor(() => expect(relay.subscriptionCount()).toBe(2));

      await expect(aliceBus.sendDm(bob.publicKey, "must stay local")).rejects.toThrow(
        `No pinned ML-KEM-768 public key for Nostr peer ${bob.publicKey}`,
      );
      expect(relay.events.filter((event) => event.kind === 4444)).toHaveLength(0);

      const [alicePublish, bobPublish] = await Promise.all([
        aliceBus.publishPqcKeyAnnouncement(),
        bobBus.publishPqcKeyAnnouncement(),
      ]);
      const [aliceDiscovery, bobDiscovery] = await Promise.all([
        bobBus.discoverPeerPqcKey(alice.publicKey),
        aliceBus.discoverPeerPqcKey(bob.publicKey),
      ]);
      const aliceAnnouncement = aliceDiscovery.announcement;
      const bobAnnouncement = bobDiscovery.announcement;
      expect(aliceAnnouncement?.fingerprint).toBe(alicePublish.fingerprint);
      expect(bobAnnouncement?.fingerprint).toBe(bobPublish.fingerprint);
      if (!aliceAnnouncement || !bobAnnouncement) {
        throw new Error("Both signed PQC key announcements must be discoverable");
      }
      expect(aliceDiscovery.sourceRelays).toEqual([relay.url]);
      expect(bobDiscovery.sourceRelays).toEqual([relay.url]);

      aliceBus.updatePinnedPeerPqcKey(bob.publicKey, bobAnnouncement.publicKey);
      bobBus.updatePinnedPeerPqcKey(alice.publicKey, aliceAnnouncement.publicKey);
      await aliceBus.sendDm(bob.publicKey, "first confirmed message");
      await bobBus.sendDm(alice.publicKey, "first confirmed reply");
      await vi.waitFor(() => expect(bobMessages).toEqual(["first confirmed message"]));
      await vi.waitFor(() => expect(aliceMessages).toEqual(["first confirmed reply"]));

      await bobBus.close();
      await vi.waitFor(() => expect(relay.subscriptionCount()).toBe(1));
      rotatedBob = rotateTestMlKemIdentity(bob);
      const rotatedBobBus = await startNostrBus({
        accountId: "bob",
        privateKey: rotatedBob.privateKey,
        mlKemSecretKey: rotatedBob.encodedMlKemSecretKey,
        mlKemPeerPublicKeys: { [alice.publicKey]: alice.encodedMlKemPublicKey },
        relays: [relay.url],
        onMessage: async (_pubkey, text) => {
          bobMessages.push(text);
        },
        onError: (error, context) => {
          if (context.startsWith("decrypt from ")) {
            rotatedBobErrors.push(error);
          }
        },
      });
      handles.push(rotatedBobBus);
      await vi.waitFor(() => expect(relay.subscriptionCount()).toBe(2));

      const rotationPublish = await rotatedBobBus.publishPqcKeyAnnouncement();
      expect(rotationPublish.previousFingerprint).toBe(bobPublish.fingerprint);
      const rotationDiscovery = await aliceBus.discoverPeerPqcKey(bob.publicKey);
      expect(rotationDiscovery.announcement).toMatchObject({
        fingerprint: rotationPublish.fingerprint,
        previousFingerprint: bobPublish.fingerprint,
      });
      const rotationAnnouncement = rotationDiscovery.announcement;
      if (!rotationAnnouncement) {
        throw new Error("The signed chained rotation must be discoverable");
      }

      await aliceBus.sendDm(bob.publicKey, "still encrypted to the old pin");
      await vi.waitFor(() => expect(rotatedBobErrors).toHaveLength(1));
      expect(bobMessages).toEqual(["first confirmed message"]);

      aliceBus.updatePinnedPeerPqcKey(bob.publicKey, rotationAnnouncement.publicKey);
      await aliceBus.sendDm(bob.publicKey, "message after confirmed rotation");
      await vi.waitFor(() =>
        expect(bobMessages).toEqual([
          "first confirmed message",
          "message after confirmed rotation",
        ]),
      );
    } finally {
      if (rotatedBob) {
        clearTestIdentity(rotatedBob);
      }
    }
  }, 45_000);

  it("fails closed when the recipient starts with the wrong ML-KEM secret key", async () => {
    const wrongBob = createTestIdentity();
    const bobMessages: string[] = [];
    const bobErrors: Error[] = [];
    try {
      const aliceBus = await startNostrBus({
        accountId: "alice",
        privateKey: alice.privateKey,
        mlKemSecretKey: alice.encodedMlKemSecretKey,
        mlKemPeerPublicKeys: { [bob.publicKey]: bob.encodedMlKemPublicKey },
        relays: [relay.url],
        onMessage: async () => {},
      });
      handles.push(aliceBus);

      const bobBus = await startNostrBus({
        accountId: "bob-wrong-key",
        privateKey: bob.privateKey,
        mlKemSecretKey: wrongBob.encodedMlKemSecretKey,
        mlKemPeerPublicKeys: { [alice.publicKey]: alice.encodedMlKemPublicKey },
        relays: [relay.url],
        onMessage: async (_pubkey, text) => {
          bobMessages.push(text);
        },
        onMetric: () => {},
        onError: (error, context) => {
          if (context.startsWith("decrypt from ")) {
            bobErrors.push(error);
          }
        },
      });
      handles.push(bobBus);
      await vi.waitFor(() => expect(relay.subscriptionCount()).toBe(2));

      await aliceBus.sendDm(bob.publicKey, "must not decrypt");
      await vi.waitFor(() => expect(bobErrors).toHaveLength(1));
      expect(bobMessages).toEqual([]);
      expect(bobBus.getMetrics().decrypt.failure).toBe(1);
      expect(bobBus.getMetrics().eventsRejected.decryptFailed).toBe(1);
    } finally {
      clearTestIdentity(wrongBob);
    }
  }, 30_000);
});
