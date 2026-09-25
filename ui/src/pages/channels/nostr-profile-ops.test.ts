// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  discoverNostrPqcKey,
  importNostrProfile,
  pinNostrPqcKey,
  publishNostrPqcKey,
  putNostrProfile,
} from "./nostr-profile-ops.ts";

const NOSTR_PROFILE_REQUEST_TIMEOUT_MS = 30_000;

function requireRequestSignal(init: RequestInit | undefined): AbortSignal {
  const signal = init?.signal;
  if (!(signal instanceof AbortSignal)) {
    throw new Error("Expected Nostr profile request to carry an AbortSignal");
  }
  return signal;
}

function rejectWhenAborted(signal: AbortSignal): Promise<never> {
  return new Promise((_resolve, reject) => {
    signal.addEventListener(
      "abort",
      () => {
        const error = new Error("Nostr request timed out after 30 seconds");
        error.name = "TimeoutError";
        reject(error);
      },
      { once: true },
    );
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("Nostr profile HTTP operations", () => {
  it("aborts a profile PUT when response headers never arrive", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn<typeof fetch>(async (_input, init) => {
      return await rejectWhenAborted(requireRequestSignal(init));
    });
    vi.stubGlobal("fetch", fetchMock);

    const request = putNostrProfile({
      accountId: "main/account",
      headers: { Authorization: "Bearer test" },
      values: { name: "Alice" },
    });
    const result = expect(request).rejects.toMatchObject({
      name: "TimeoutError",
      message: "Nostr request timed out after 30 seconds",
    });
    await vi.advanceTimersByTimeAsync(NOSTR_PROFILE_REQUEST_TIMEOUT_MS);
    await result;

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/channels/nostr/main%2Faccount/profile",
      expect.objectContaining({
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer test",
        },
        body: JSON.stringify({ name: "Alice" }),
        signal: expect.any(AbortSignal),
      }),
    );
    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });

  it("keeps the import deadline active while the response body is pending", async () => {
    vi.useFakeTimers();
    const fetchMock = vi.fn<typeof fetch>(async (_input, init) => {
      const signal = requireRequestSignal(init);
      return {
        ok: true,
        status: 200,
        json: () => rejectWhenAborted(signal),
      } as unknown as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    const request = importNostrProfile({ accountId: "default", headers: {} });
    const result = expect(request).rejects.toMatchObject({ name: "TimeoutError" });
    await vi.advanceTimersByTimeAsync(NOSTR_PROFILE_REQUEST_TIMEOUT_MS);
    await result;

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/channels/nostr/default/profile/import",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ autoMerge: true }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("preserves successful JSON responses for PUT and import", async () => {
    const putResponse = new Response(JSON.stringify({ ok: true, persisted: true }), {
      status: 200,
    });
    const importResponse = new Response(
      JSON.stringify({ ok: true, saved: true, merged: { name: "Alice" } }),
      { status: 200 },
    );
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(putResponse)
      .mockResolvedValueOnce(importResponse);
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      putNostrProfile({ accountId: "default", headers: {}, values: { name: "Alice" } }),
    ).resolves.toEqual({ data: { ok: true, persisted: true }, response: putResponse });
    await expect(importNostrProfile({ accountId: "default", headers: {} })).resolves.toEqual({
      data: { ok: true, saved: true, merged: { name: "Alice" } },
      response: importResponse,
    });
  });

  it("preserves the response when an error body is not JSON", async () => {
    const response = new Response("gateway unavailable", { status: 503 });
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockResolvedValue(response));

    await expect(importNostrProfile({ accountId: "default", headers: {} })).resolves.toEqual({
      data: null,
      response,
    });
  });

  it("encodes account and peer identifiers for PQC discovery", async () => {
    const response = new Response(
      JSON.stringify({
        ok: true,
        peerPubkey: "npub1peer",
        pinnedFingerprint: null,
        trustState: "not-found",
        announcement: null,
        relaysQueried: [],
        sourceRelays: [],
      }),
      { status: 200 },
    );
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(response);
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      discoverNostrPqcKey({
        accountId: "main/account",
        peerPubkey: "npub1peer/unsafe",
        headers: { Authorization: "Bearer test" },
      }),
    ).resolves.toMatchObject({ response });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/channels/nostr/main%2Faccount/pqc-keys/npub1peer%2Funsafe",
      expect.objectContaining({
        method: "GET",
        headers: { Authorization: "Bearer test" },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("sends an explicit fingerprint and compare-and-set value when pinning", async () => {
    const fingerprint = `sha256:${"a".repeat(64)}`;
    const previous = `sha256:${"b".repeat(64)}`;
    const response = new Response(JSON.stringify({ ok: true, updated: true }), { status: 200 });
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(response);
    vi.stubGlobal("fetch", fetchMock);

    await pinNostrPqcKey({
      accountId: "default",
      peerPubkey: "npub1peer",
      fingerprint,
      expectedCurrentFingerprint: previous,
      headers: {},
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/channels/nostr/default/pqc-keys/npub1peer",
      expect.objectContaining({
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fingerprint,
          expectedCurrentFingerprint: previous,
        }),
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("publishes the local PQC announcement without an unnecessary request body", async () => {
    const response = new Response(JSON.stringify({ ok: true, successes: [], failures: [] }), {
      status: 200,
    });
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(response);
    vi.stubGlobal("fetch", fetchMock);

    await publishNostrPqcKey({
      accountId: "default",
      headers: { Authorization: "Bearer test" },
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/channels/nostr/default/pqc-keys/publish",
      expect.objectContaining({
        method: "POST",
        headers: { Authorization: "Bearer test" },
        signal: expect.any(AbortSignal),
      }),
    );
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBeUndefined();
  });
});
