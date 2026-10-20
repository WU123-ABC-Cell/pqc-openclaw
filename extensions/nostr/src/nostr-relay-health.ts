import type { NostrMetrics } from "./metrics.js";

const CIRCUIT_BREAKER_THRESHOLD = 5;
const CIRCUIT_BREAKER_RESET_MS = 30000;
const HEALTH_WINDOW_MS = 60000;

interface CircuitBreakerState {
  state: "closed" | "open" | "half_open";
  failures: number;
  lastFailure: number;
  lastSuccess: number;
}

export interface CircuitBreaker {
  canAttempt: () => boolean;
  recordSuccess: () => void;
  recordFailure: () => void;
  getState: () => CircuitBreakerState["state"];
}

export function createCircuitBreaker(
  relay: string,
  metrics: NostrMetrics,
  threshold: number = CIRCUIT_BREAKER_THRESHOLD,
  resetMs: number = CIRCUIT_BREAKER_RESET_MS,
): CircuitBreaker {
  const state: CircuitBreakerState = {
    state: "closed",
    failures: 0,
    lastFailure: 0,
    lastSuccess: Date.now(),
  };

  return {
    canAttempt(): boolean {
      if (state.state === "closed") {
        return true;
      }
      if (state.state === "open") {
        if (Date.now() - state.lastFailure >= resetMs) {
          state.state = "half_open";
          metrics.emit("relay.circuit_breaker.half_open", 1, { relay });
          return true;
        }
        return false;
      }
      return true;
    },

    recordSuccess(): void {
      if (state.state === "half_open") {
        state.state = "closed";
        state.failures = 0;
        metrics.emit("relay.circuit_breaker.close", 1, { relay });
      } else if (state.state === "closed") {
        state.failures = 0;
      }
      state.lastSuccess = Date.now();
    },

    recordFailure(): void {
      state.failures++;
      state.lastFailure = Date.now();
      if (state.state === "half_open") {
        state.state = "open";
        metrics.emit("relay.circuit_breaker.open", 1, { relay });
      } else if (state.state === "closed" && state.failures >= threshold) {
        state.state = "open";
        metrics.emit("relay.circuit_breaker.open", 1, { relay });
      }
    },

    getState(): CircuitBreakerState["state"] {
      return state.state;
    },
  };
}

interface RelayHealthStats {
  successCount: number;
  failureCount: number;
  latencySum: number;
  latencyCount: number;
  lastSuccess: number;
  lastFailure: number;
}

export interface RelayHealthTracker {
  recordSuccess: (relay: string, latencyMs: number) => void;
  recordFailure: (relay: string) => void;
  getScore: (relay: string) => number;
  getSortedRelays: (relays: string[]) => string[];
}

export function createRelayHealthTracker(): RelayHealthTracker {
  const stats = new Map<string, RelayHealthStats>();

  function getOrCreate(relay: string): RelayHealthStats {
    let s = stats.get(relay);
    if (!s) {
      s = {
        successCount: 0,
        failureCount: 0,
        latencySum: 0,
        latencyCount: 0,
        lastSuccess: 0,
        lastFailure: 0,
      };
      stats.set(relay, s);
    }
    return s;
  }

  return {
    recordSuccess(relay: string, latencyMs: number): void {
      const s = getOrCreate(relay);
      s.successCount++;
      s.latencySum += latencyMs;
      s.latencyCount++;
      s.lastSuccess = Date.now();
    },

    recordFailure(relay: string): void {
      const s = getOrCreate(relay);
      s.failureCount++;
      s.lastFailure = Date.now();
    },

    getScore(relay: string): number {
      const s = stats.get(relay);
      if (!s) {
        return 0.5;
      }
      const total = s.successCount + s.failureCount;
      if (total === 0) {
        return 0.5;
      }
      const successRate = s.successCount / total;
      const now = Date.now();
      const recencyBonus =
        s.lastSuccess > s.lastFailure
          ? Math.max(0, 1 - (now - s.lastSuccess) / HEALTH_WINDOW_MS) * 0.2
          : 0;
      const avgLatency = s.latencyCount > 0 ? s.latencySum / s.latencyCount : 1000;
      const latencyPenalty = Math.min(0.2, avgLatency / 10000);
      return Math.max(0, Math.min(1, successRate + recencyBonus - latencyPenalty));
    },

    getSortedRelays(relays: string[]): string[] {
      return [...relays].toSorted((a, b) => this.getScore(b) - this.getScore(a));
    },
  };
}
