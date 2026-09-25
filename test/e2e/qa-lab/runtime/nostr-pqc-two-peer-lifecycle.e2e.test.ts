// Two isolated Gateway processes exercise the public Nostr PQC lifecycle through a local relay.
import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { generateSecretKey, getPublicKey, verifyEvent, type Event, type Filter } from "nostr-tools";
import { openClawPqcDm } from "openclaw/plugin-sdk/security-runtime";
import { afterEach, describe, expect, it, vi } from "vitest";
import WebSocket, { WebSocketServer, type RawData } from "ws";
import {
  connectGatewayClient,
  disconnectGatewayClient,
} from "../../../../src/gateway/test-helpers.e2e.js";
import { buildMockOpenAiResponsesProvider } from "../../../../src/gateway/test-openai-responses-model.js";
import {
  createOpenClawTestInstance,
  type OpenClawTestInstance,
} from "../../../helpers/openclaw-test-instance.js";

type Identity = {
  nostrSecret: Uint8Array;
  nostrPrivate: string;
  nostrPublic: string;
  mlKemPublic: Uint8Array;
  mlKemSecret: Uint8Array;
  encodedMlKemSecret: string;
};

function createIdentity(): Identity {
  const nostrSecret = generateSecretKey();
  const mlKem = openClawPqcDm.generateMlKem768KeyPair();
  return {
    nostrSecret,
    nostrPrivate: Buffer.from(nostrSecret).toString("hex"),
    nostrPublic: getPublicKey(nostrSecret),
    mlKemPublic: mlKem.publicKey,
    mlKemSecret: mlKem.secretKey,
    encodedMlKemSecret: openClawPqcDm.encodeMlKemKey(mlKem.secretKey),
  };
}

function clearIdentity(identity: Identity): void {
  identity.nostrSecret.fill(0);
  identity.mlKemPublic.fill(0);
  identity.mlKemSecret.fill(0);
}

type Subscription = { socket: WebSocket; id: string; filters: Filter[] };

function matchesFilter(event: Event, filter: Filter): boolean {
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
  for (const [key, values] of Object.entries(filter)) {
    if (!key.startsWith("#") || !Array.isArray(values)) {
      continue;
    }
    if (
      !event.tags.some(
        (tag) => tag[0] === key.slice(1) && (values as string[]).includes(tag[1] ?? ""),
      )
    ) {
      return false;
    }
  }
  return true;
}

class LocalRelay {
  readonly events: Event[] = [];
  readonly url: string;
  private readonly subscriptions = new Set<Subscription>();

  private constructor(
    private readonly server: Server,
    private readonly sockets: WebSocketServer,
  ) {
    this.url = `ws://127.0.0.1:${(server.address() as AddressInfo).port}`;
    sockets.on("connection", (socket) => {
      socket.on("message", (data) => this.onMessage(socket, data));
      socket.on("close", () => {
        for (const subscription of this.subscriptions) {
          if (subscription.socket === socket) {
            this.subscriptions.delete(subscription);
          }
        }
      });
    });
  }

  static async start(): Promise<LocalRelay> {
    const server = createServer();
    const sockets = new WebSocketServer({ server });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    return new LocalRelay(server, sockets);
  }

  async close(): Promise<void> {
    for (const socket of this.sockets.clients) {
      socket.terminate();
    }
    await new Promise<void>((resolve) => {
      this.sockets.close(() => resolve());
    });
    await new Promise<void>((resolve, reject) => {
      this.server.close((error) => (error ? reject(error) : resolve()));
    });
  }

  private onMessage(socket: WebSocket, data: RawData): void {
    let frame: unknown;
    try {
      frame = JSON.parse(data.toString()) as unknown;
    } catch {
      return;
    }
    if (!Array.isArray(frame) || typeof frame[0] !== "string") {
      return;
    }
    if (frame[0] === "REQ" && typeof frame[1] === "string") {
      const subscription: Subscription = {
        socket,
        id: frame[1],
        filters: frame
          .slice(2)
          .filter((filter): filter is Filter => typeof filter === "object" && filter !== null),
      };
      this.subscriptions.add(subscription);
      for (const event of this.events) {
        if (subscription.filters.some((filter) => matchesFilter(event, filter))) {
          this.send(socket, ["EVENT", subscription.id, event]);
        }
      }
      this.send(socket, ["EOSE", subscription.id]);
      return;
    }
    if (frame[0] === "CLOSE" && typeof frame[1] === "string") {
      for (const subscription of this.subscriptions) {
        if (subscription.socket === socket && subscription.id === frame[1]) {
          this.subscriptions.delete(subscription);
        }
      }
      return;
    }
    if (frame[0] !== "EVENT" || typeof frame[1] !== "object" || frame[1] === null) {
      return;
    }
    const event = frame[1] as Event;
    if (!verifyEvent(event)) {
      this.send(socket, ["OK", event.id, false, "invalid: signature"]);
      return;
    }
    this.events.push(event);
    this.send(socket, ["OK", event.id, true, "stored"]);
    for (const subscription of this.subscriptions) {
      if (subscription.filters.some((filter) => matchesFilter(event, filter))) {
        this.send(subscription.socket, ["EVENT", subscription.id, event]);
      }
    }
  }

  private send(socket: WebSocket, frame: unknown): void {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(frame));
    }
  }
}

type JsonBody = Record<string, unknown>;

async function requestPqc(
  instance: OpenClawTestInstance,
  path: string,
  method = "GET",
  body?: JsonBody,
): Promise<{ status: number; body: JsonBody }> {
  const response = await fetch(`http://127.0.0.1:${instance.port}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${instance.gatewayToken}`,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(15_000),
  });
  return { status: response.status, body: (await response.json()) as JsonBody };
}

describe("Nostr PQC two-Gateway public lifecycle", () => {
  const instances: OpenClawTestInstance[] = [];
  const identities: Identity[] = [];
  let relay: LocalRelay | undefined;
  let modelServer: Server | undefined;

  afterEach(async () => {
    await Promise.allSettled(instances.splice(0).map((instance) => instance.cleanup()));
    if (relay) {
      await relay.close();
      relay = undefined;
    }
    if (modelServer?.listening) {
      await new Promise<void>((resolve) => {
        modelServer?.close(() => resolve());
      });
      modelServer = undefined;
    }
    for (const identity of identities.splice(0)) {
      clearIdentity(identity);
    }
  });

  it(
    "requires confirmed pins, rejects stale keys, and resumes after a chained rotation",
    { timeout: 180_000 },
    async () => {
      relay = await LocalRelay.start();
      const alice = createIdentity();
      const bob = createIdentity();
      identities.push(alice, bob);

      const providerRequests: string[] = [];
      modelServer = createServer((request, response) => {
        const chunks: Buffer[] = [];
        request.on("data", (chunk: Buffer) => chunks.push(chunk));
        request.on("end", () => {
          providerRequests.push(Buffer.concat(chunks).toString("utf8"));
          const message = {
            type: "message",
            id: randomUUID(),
            role: "assistant",
            status: "completed",
            content: [{ type: "output_text", text: "PQC_GATEWAY_REPLY", annotations: [] }],
          };
          response.writeHead(200, { "content-type": "text/event-stream" });
          response.end(
            [
              {
                type: "response.output_item.added",
                output_index: 0,
                item: { ...message, status: "in_progress", content: [] },
              },
              { type: "response.output_item.done", output_index: 0, item: message },
              {
                type: "response.completed",
                response: {
                  status: "completed",
                  usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 },
                },
              },
            ]
              .map((event) => `data: ${JSON.stringify(event)}\n\n`)
              .join("") + "data: [DONE]\n\n",
          );
        });
      });
      await new Promise<void>((resolve, reject) => {
        modelServer?.once("error", reject);
        modelServer?.listen(0, "127.0.0.1", resolve);
      });
      const modelPort = (modelServer.address() as AddressInfo).port;
      const provider = buildMockOpenAiResponsesProvider(`http://127.0.0.1:${modelPort}/v1`);

      for (const [name, local] of [
        ["alice", alice],
        ["bob", bob],
      ] as const) {
        const instance = await createOpenClawTestInstance({
          name: `nostr-pqc-${name}`,
          env: {
            OPENCLAW_SKIP_CHANNELS: undefined,
            OPENCLAW_SKIP_PROVIDERS: undefined,
            OPENCLAW_TEST_MINIMAL_GATEWAY: undefined,
          },
          config: {
            plugins: { entries: { nostr: { enabled: true } } },
            agents: { defaults: { skipBootstrap: true, model: { primary: provider.modelRef } } },
            models: { mode: "replace", providers: { [provider.providerId]: provider.config } },
            channels: {
              nostr: {
                enabled: true,
                privateKey: local.nostrPrivate,
                mlKemSecretKey: local.encodedMlKemSecret,
                relays: [relay.url],
                dmPolicy: name === "bob" ? "open" : "disabled",
                allowFrom: name === "bob" ? ["*"] : [],
              },
            },
          },
        });
        instances.push(instance);
        await instance.startGateway();
      }
      const [aliceGateway, bobGateway] = instances;
      if (!aliceGateway || !bobGateway) {
        throw new Error("both isolated Gateways must have started");
      }
      const aliceClient = await connectGatewayClient({
        url: aliceGateway.url,
        token: aliceGateway.gatewayToken,
        role: "operator",
        scopes: ["operator.admin", "operator.read", "operator.write"],
      });
      const bobClient = await connectGatewayClient({
        url: bobGateway.url,
        token: bobGateway.gatewayToken,
        role: "operator",
        scopes: ["operator.admin", "operator.read", "operator.write"],
      });
      try {
        const send = async (message: string) =>
          await aliceClient.request("send", {
            channel: "nostr",
            accountId: "default",
            to: bob.nostrPublic,
            message,
            idempotencyKey: randomUUID(),
          });
        await expect(send("must not leave Alice without a pin")).rejects.toThrow();
        expect(relay.events.filter((event) => event.kind === 4444)).toHaveLength(0);

        const alicePath = `/api/channels/nostr/default/pqc-keys/${bob.nostrPublic}`;
        const bobPath = `/api/channels/nostr/default/pqc-keys/${alice.nostrPublic}`;
        const aliceDiscovery = await requestPqc(aliceGateway, alicePath);
        const bobDiscovery = await requestPqc(bobGateway, bobPath);
        expect(aliceDiscovery.status, aliceGateway.logs()).toBe(200);
        expect(bobDiscovery.status, bobGateway.logs()).toBe(200);
        expect(aliceDiscovery.body.trustState).toBe("untrusted-first-key");
        expect(bobDiscovery.body.trustState).toBe("untrusted-first-key");
        const bobAnnouncement = aliceDiscovery.body.announcement as { fingerprint: string };
        const aliceAnnouncement = bobDiscovery.body.announcement as { fingerprint: string };
        const alicePin = await requestPqc(aliceGateway, alicePath, "PUT", {
          fingerprint: bobAnnouncement.fingerprint,
          expectedCurrentFingerprint: null,
        });
        const bobPin = await requestPqc(bobGateway, bobPath, "PUT", {
          fingerprint: aliceAnnouncement.fingerprint,
          expectedCurrentFingerprint: null,
        });
        expect(alicePin, aliceGateway.logs()).toMatchObject({
          status: 200,
          body: { ok: true, updated: true },
        });
        expect(bobPin, bobGateway.logs()).toMatchObject({
          status: 200,
          body: { ok: true, updated: true },
        });

        await send("PQC_GATEWAY_REQUEST");
        await vi.waitFor(
          () => {
            expect(
              relay?.events.some(
                (event) =>
                  event.kind === 4444 &&
                  event.pubkey === alice.nostrPublic &&
                  event.content.startsWith("ocpqc1:"),
              ),
            ).toBe(true);
          },
          { timeout: 30_000 },
        );
        try {
          await vi.waitFor(
            () => {
              expect(
                relay?.events.some(
                  (event) =>
                    event.kind === 4444 &&
                    event.pubkey === bob.nostrPublic &&
                    event.content.startsWith("ocpqc1:"),
                ),
              ).toBe(true);
            },
            { timeout: 30_000 },
          );
        } catch (error) {
          throw new Error(`Bob did not reply: ${String(error)}\n${bobGateway.logs()}`, {
            cause: error,
          });
        }
        expect(providerRequests.some((body) => body.includes("PQC_GATEWAY_REQUEST"))).toBe(true);

        const initialBobReplies = relay.events.filter(
          (event) => event.kind === 4444 && event.pubkey === bob.nostrPublic,
        ).length;
        const rotatedMlKem = openClawPqcDm.generateMlKem768KeyPair();
        const rotatedSecret = openClawPqcDm.encodeMlKemKey(rotatedMlKem.secretKey);
        identities.push({
          ...bob,
          mlKemPublic: rotatedMlKem.publicKey,
          mlKemSecret: rotatedMlKem.secretKey,
          encodedMlKemSecret: rotatedSecret,
        });
        const beforeRotation = await bobClient.request<{ hash?: string }>("config.get", {});
        if (!beforeRotation.hash) {
          throw new Error("Bob Gateway did not provide a config revision hash");
        }
        await bobClient.request("config.patch", {
          raw: JSON.stringify({ channels: { nostr: { mlKemSecretKey: rotatedSecret } } }),
          baseHash: beforeRotation.hash,
          restartDelayMs: 0,
        });

        let rotationDiscovery: Awaited<ReturnType<typeof requestPqc>> | undefined;
        await vi.waitFor(
          async () => {
            rotationDiscovery = await requestPqc(aliceGateway, alicePath);
            expect(rotationDiscovery.status).toBe(200);
            expect(rotationDiscovery.body.trustState).toBe("untrusted-rotation");
          },
          { timeout: 30_000 },
        );
        const rotatedAnnouncement = rotationDiscovery?.body.announcement as
          | { fingerprint: string; previousFingerprint?: string }
          | undefined;
        expect(rotatedAnnouncement?.previousFingerprint).toBe(bobAnnouncement.fingerprint);
        if (!rotatedAnnouncement) {
          throw new Error("Bob's signed rotation announcement was not discovered");
        }

        const staleConfirmation = await requestPqc(aliceGateway, alicePath, "PUT", {
          fingerprint: rotatedAnnouncement.fingerprint,
          expectedCurrentFingerprint: null,
        });
        expect(staleConfirmation.status).toBe(409);
        const oldCandidate = await requestPqc(aliceGateway, alicePath, "PUT", {
          fingerprint: bobAnnouncement.fingerprint,
          expectedCurrentFingerprint: bobAnnouncement.fingerprint,
        });
        expect(oldCandidate.status).toBe(409);

        await send("PQC_OLD_PIN_AFTER_ROTATION");
        await vi.waitFor(
          () => {
            expect(bobGateway.logs()).toContain(`Nostr error (decrypt from ${alice.nostrPublic})`);
          },
          { timeout: 30_000 },
        );
        expect(providerRequests.some((body) => body.includes("PQC_OLD_PIN_AFTER_ROTATION"))).toBe(
          false,
        );
        expect(
          relay.events.filter((event) => event.kind === 4444 && event.pubkey === bob.nostrPublic),
        ).toHaveLength(initialBobReplies);

        const confirmedRotation = await requestPqc(aliceGateway, alicePath, "PUT", {
          fingerprint: rotatedAnnouncement.fingerprint,
          expectedCurrentFingerprint: bobAnnouncement.fingerprint,
        });
        expect(confirmedRotation, aliceGateway.logs()).toMatchObject({
          status: 200,
          body: { ok: true, updated: true },
        });
        await send("PQC_ROTATED_KEY_REQUEST");
        await vi.waitFor(
          () => {
            expect(providerRequests.some((body) => body.includes("PQC_ROTATED_KEY_REQUEST"))).toBe(
              true,
            );
            expect(
              relay?.events.filter(
                (event) => event.kind === 4444 && event.pubkey === bob.nostrPublic,
              ).length,
            ).toBeGreaterThan(initialBobReplies);
          },
          { timeout: 30_000 },
        );
      } finally {
        await Promise.all([
          disconnectGatewayClient(aliceClient),
          disconnectGatewayClient(bobClient),
        ]);
      }
    },
  );
});
