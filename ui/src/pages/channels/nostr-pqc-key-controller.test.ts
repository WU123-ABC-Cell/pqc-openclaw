// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";
import { NostrPqcKeyController } from "./nostr-pqc-key-controller.ts";

const CANDIDATE_FINGERPRINT = `sha256:${"a".repeat(64)}`;
const LOCAL_FINGERPRINT = `sha256:${"d".repeat(64)}`;

function createHarness() {
  let generation = 0;
  const requestUpdate = vi.fn();
  const controller = new NostrPqcKeyController({
    beginOperation: () => {
      generation += 1;
      const captured = generation;
      return {
        accountId: "default",
        headers: { Authorization: "Bearer test" },
        isCurrent: () => generation === captured,
      };
    },
    invalidateOperations: () => {
      generation += 1;
    },
    requestUpdate,
  });
  return { controller, requestUpdate };
}

function discoveryResponse() {
  return {
    ok: true,
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
  } as const;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("NostrPqcKeyController", () => {
  it("stores relay discovery as untrusted without pinning it", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(new Response(JSON.stringify(discoveryResponse()), { status: 200 })),
    );
    const { controller } = createHarness();
    controller.setPeerPubkey("npub1peer");

    await controller.discover();

    expect(controller.state.discovery?.trustState).toBe("untrusted-first-key");
    expect(controller.state.discovery?.pinnedFingerprint).toBeNull();
    expect(controller.state.confirmedFingerprint).toBe("");
  });

  it("does not issue a pin request until the complete fingerprint matches", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify(discoveryResponse()), { status: 200 }))
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ok: true,
            updated: true,
            announcement: discoveryResponse().announcement,
          }),
          { status: 200 },
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const { controller } = createHarness();
    controller.setPeerPubkey("npub1peer");
    await controller.discover();

    controller.setConfirmedFingerprint(`sha256:${"b".repeat(64)}`);
    await controller.pin();
    expect(fetchMock).toHaveBeenCalledOnce();

    controller.setConfirmedFingerprint(CANDIDATE_FINGERPRINT);
    await controller.pin();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(controller.state.discovery?.trustState).toBe("pinned");
    expect(controller.state.discovery?.pinnedFingerprint).toBe(CANDIDATE_FINGERPRINT);
  });

  it("ignores a discovery response after the operator changes peers", async () => {
    let resolveResponse: ((response: Response) => void) | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockImplementation(
        async () =>
          await new Promise<Response>((resolve) => {
            resolveResponse = resolve;
          }),
      ),
    );
    const { controller } = createHarness();
    controller.setPeerPubkey("npub1old");
    const pending = controller.discover();
    await vi.waitFor(() => expect(resolveResponse).toBeTypeOf("function"));

    controller.setPeerPubkey("npub1new");
    resolveResponse?.(new Response(JSON.stringify(discoveryResponse()), { status: 200 }));
    await pending;

    expect(controller.state.peerPubkey).toBe("npub1new");
    expect(controller.state.discovery).toBeNull();
  });

  it("keeps the published local fingerprint available for out-of-band verification", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockResolvedValue(
        new Response(
          JSON.stringify({
            ok: true,
            eventId: "event-id",
            pubkey: "f".repeat(64),
            createdAt: 1_800_000_000,
            publicKey: "base64-key",
            fingerprint: LOCAL_FINGERPRINT,
            successes: ["wss://relay.example"],
            failures: [],
          }),
          { status: 200 },
        ),
      ),
    );
    const { controller } = createHarness();

    await controller.publish();

    expect(controller.state.publishedFingerprint).toBe(LOCAL_FINGERPRINT);
  });
});
