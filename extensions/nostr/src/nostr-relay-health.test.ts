import { afterEach, describe, expect, it, vi } from "vitest";
import { createMetrics, type MetricEvent } from "./metrics.js";
import { createCircuitBreaker, createRelayHealthTracker } from "./nostr-relay-health.js";

afterEach(() => vi.useRealTimers());

describe("Nostr relay health", () => {
  it("opens, half-opens and closes a relay circuit with the same metrics", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const events: MetricEvent[] = [];
    const breaker = createCircuitBreaker(
      "wss://relay.example",
      createMetrics((event) => {
        events.push(event);
      }),
      2,
      1_000,
    );

    breaker.recordFailure();
    expect(breaker.getState()).toBe("closed");
    breaker.recordFailure();
    expect(breaker.getState()).toBe("open");
    expect(breaker.canAttempt()).toBe(false);

    vi.advanceTimersByTime(1_000);
    expect(breaker.canAttempt()).toBe(true);
    expect(breaker.getState()).toBe("half_open");
    breaker.recordSuccess();
    expect(breaker.getState()).toBe("closed");
    expect(events.map((event) => event.name)).toEqual([
      "relay.circuit_breaker.open",
      "relay.circuit_breaker.half_open",
      "relay.circuit_breaker.close",
    ]);
  });

  it("sorts successful relays ahead of failing relays", () => {
    const tracker = createRelayHealthTracker();
    tracker.recordFailure("wss://slow.example");
    tracker.recordSuccess("wss://fast.example", 5);

    expect(tracker.getSortedRelays(["wss://slow.example", "wss://fast.example"])).toEqual([
      "wss://fast.example",
      "wss://slow.example",
    ]);
  });
});
