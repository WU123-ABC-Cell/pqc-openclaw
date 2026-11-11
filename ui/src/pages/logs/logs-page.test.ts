/* @vitest-environment jsdom */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { GatewayBrowserClient } from "../../api/gateway.ts";
import type { ApplicationContext, ApplicationGatewaySnapshot } from "../../app/context.ts";
import "./logs-page.ts";

type TestLogsPage = HTMLElement & {
  context: ApplicationContext;
  connected: boolean;
  logsAutoFollow: boolean;
  logsEntries: unknown[];
  logsStatus: { error: string | null; hasLoaded: boolean; stale: boolean };
  streamFollow: {
    atBottom: boolean;
    schedule: (force?: boolean) => void;
  };
  readonly updateComplete: Promise<boolean>;
  applyGatewaySnapshot: (snapshot: ApplicationGatewaySnapshot) => void;
  loadLogs: (opts?: { reset?: boolean; quiet?: boolean }) => Promise<boolean>;
  requestUpdate: () => void;
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function contextWithClient(client: GatewayBrowserClient): ApplicationContext {
  return {
    basePath: "",
    gateway: {
      snapshot: { client, phase: "stopped" },
      subscribe: () => () => undefined,
    },
    navigate: vi.fn(),
    preload: vi.fn(async () => undefined),
  } as unknown as ApplicationContext;
}

describe("LogsPage lifecycle", () => {
  afterEach(() => {
    document.body.replaceChildren();
    vi.restoreAllMocks();
  });

  it("does not schedule scroll work after disconnect", async () => {
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = {
      basePath: "",
      gateway: {
        snapshot: { client: null, phase: "stopped" },
        subscribe: () => () => undefined,
      },
      navigate: vi.fn(),
      preload: vi.fn(async () => undefined),
    } as unknown as ApplicationContext;
    const requestFrame = vi.spyOn(window, "requestAnimationFrame").mockReturnValue(1);

    document.body.append(page);
    await page.updateComplete;
    await Promise.resolve();
    requestFrame.mockClear();

    page.streamFollow.schedule();
    page.remove();
    await Promise.resolve();

    expect(requestFrame).not.toHaveBeenCalled();
  });

  it("forces a scroll when auto-follow is re-enabled away from the bottom", async () => {
    const client = {
      request: vi.fn(
        () =>
          new Promise(() => {
            // Keep any incidental request pending; this test only exercises scroll state.
          }),
      ),
    } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;

    page.logsAutoFollow = false;
    await page.updateComplete;
    const scheduleScroll = vi.spyOn(page.streamFollow, "schedule");
    page.streamFollow.atBottom = false;
    page.logsAutoFollow = true;
    await page.updateComplete;

    expect(scheduleScroll).toHaveBeenCalledOnce();
    expect(scheduleScroll).toHaveBeenCalledWith(true);
  });

  it("discards a log response from a replaced gateway source that reuses its client", async () => {
    const pending = deferred<{ cursor: number; lines: string[]; reset: boolean }>();
    const client = {
      request: vi.fn(() => pending.promise),
    } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;
    page.connected = true;

    const load = page.loadLogs({ reset: true });
    page.context = contextWithClient(client);
    page.requestUpdate();
    await page.updateComplete;
    pending.resolve({ cursor: 1, lines: ["stale"], reset: true });
    await load;

    expect(page.logsEntries).toEqual([]);
  });

  it("discards a log response that completes after disconnect", async () => {
    const pending = deferred<{ cursor: number; lines: string[]; reset: boolean }>();
    const client = {
      request: vi.fn(() => pending.promise),
    } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;
    page.connected = true;

    const load = page.loadLogs({ reset: true });
    page.remove();
    pending.resolve({ cursor: 1, lines: ["stale"], reset: true });
    await load;

    expect(page.logsEntries).toEqual([]);
  });

  it("discards a log response when the gateway disconnects with the same client", async () => {
    const pending = deferred<{ cursor: number; lines: string[]; reset: boolean }>();
    const client = {
      request: vi.fn(() => pending.promise),
    } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;
    page.connected = true;

    const load = page.loadLogs({ reset: true });
    page.applyGatewaySnapshot({ client, phase: "stopped" } as ApplicationGatewaySnapshot);
    pending.resolve({ cursor: 1, lines: ["stale"], reset: true });
    await load;

    expect(page.logsEntries).toEqual([]);
  });

  it("serializes quiet polls so an older cursor cannot overwrite a newer one", async () => {
    const pending = deferred<{ cursor: number; lines: string[]; reset: boolean }>();
    const request = vi.fn(() => pending.promise);
    const client = {
      request,
    } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;
    page.connected = true;

    const first = page.loadLogs({ quiet: true });
    const second = page.loadLogs({ quiet: true });
    expect(request).toHaveBeenCalledTimes(1);
    expect(await second).toBe(false);

    pending.resolve({ cursor: 2, lines: ["fresh"], reset: true });
    expect(await first).toBe(true);
    expect(page.logsEntries).toHaveLength(1);
  });

  it("keeps the first log page when connected snapshots arrive before it completes", async () => {
    const first = deferred<{ cursor: number; lines: string[]; reset: boolean }>();
    const request = vi
      .fn()
      .mockImplementationOnce(() => first.promise)
      .mockResolvedValueOnce({ cursor: 201, lines: ["line 201"], reset: false });
    const client = { request } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;

    const connected = { client, phase: "connected" } as ApplicationGatewaySnapshot;
    page.applyGatewaySnapshot(connected);
    page.applyGatewaySnapshot(connected);
    expect(request).toHaveBeenCalledTimes(1);

    first.resolve({
      cursor: 200,
      lines: Array.from({ length: 200 }, (_, index) => `line ${index + 1}`),
      reset: true,
    });
    await vi.waitFor(() => expect(page.logsEntries).toHaveLength(200));
    await page.loadLogs({ quiet: true });
    expect(request.mock.calls[1]?.[1]).toMatchObject({ cursor: 200 });
    expect(page.logsEntries).toHaveLength(201);
  });

  it("starts a fresh first read after a same-client reconnect", async () => {
    const stale = deferred<{ cursor: number; lines: string[]; reset: boolean }>();
    const request = vi
      .fn()
      .mockImplementationOnce(() => stale.promise)
      .mockResolvedValueOnce({ cursor: 1, lines: ["current"], reset: true });
    const client = { request } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;

    page.applyGatewaySnapshot({ client, phase: "connected" } as ApplicationGatewaySnapshot);
    page.applyGatewaySnapshot({ client, phase: "stopped" } as ApplicationGatewaySnapshot);
    page.applyGatewaySnapshot({ client, phase: "connected" } as ApplicationGatewaySnapshot);
    await vi.waitFor(() => expect(page.logsEntries).toHaveLength(1));
    expect(request).toHaveBeenCalledTimes(2);

    stale.resolve({ cursor: 1, lines: ["stale"], reset: true });
    await Promise.resolve();
    expect(page.logsEntries).toEqual([expect.objectContaining({ raw: "current" })]);
  });

  it("retains loaded logs as stale after failure and clears the marker on retry success", async () => {
    const request = vi
      .fn()
      .mockResolvedValueOnce({ cursor: 1, lines: ["old"], reset: true })
      .mockRejectedValueOnce(new Error("logs unavailable"))
      .mockResolvedValueOnce({ cursor: 2, lines: ["fresh"], reset: true });
    const client = { request } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    document.body.append(page);
    await page.updateComplete;
    page.connected = true;

    await page.loadLogs({ reset: true });
    await page.loadLogs({ reset: true });
    expect(page.logsEntries).toHaveLength(1);
    expect(page.logsStatus).toEqual({
      error: "Error: logs unavailable",
      hasLoaded: true,
      stale: true,
    });

    await page.loadLogs({ reset: true });
    expect(page.logsStatus).toEqual({ error: null, hasLoaded: true, stale: false });
    expect(page.logsEntries).toHaveLength(1);
  });

  it("drops deferred scroll work after a same-client reconnect", async () => {
    const client = {
      request: vi.fn(
        () =>
          new Promise(() => {
            // Keep both connection-epoch requests pending while scroll ownership changes.
          }),
      ),
    } as unknown as GatewayBrowserClient;
    const page = document.createElement("openclaw-logs-page") as TestLogsPage;
    page.context = contextWithClient(client);
    const requestFrame = vi.spyOn(window, "requestAnimationFrame").mockReturnValue(1);
    document.body.append(page);
    await page.updateComplete;
    page.applyGatewaySnapshot({ client, phase: "connected" } as ApplicationGatewaySnapshot);
    requestFrame.mockClear();

    page.streamFollow.schedule();
    page.applyGatewaySnapshot({ client, phase: "stopped" } as ApplicationGatewaySnapshot);
    page.applyGatewaySnapshot({ client, phase: "connected" } as ApplicationGatewaySnapshot);
    await Promise.resolve();

    expect(requestFrame).not.toHaveBeenCalled();
  });
});
