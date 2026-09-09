// mlock-helper.test.ts — verify defensive behavior on Node 22 (no-op + warn once)
// and the M6.B v2 N-API native addon path on Node 24+ where the addon
// is built.
//
// (PQC whitepaper §6.3 v2, 2026-09-01 follow-up + 2026-09-05 N-API.)
//
// Three paths exercised by these tests:
//   1. Node 24+ stable process.mlock (path 1) — same assertions as before
//      but provider string now includes "(backend=process)".
//   2. Node 24.15+ with the N-API addon (path 2) — verified here via
//      the `(backend=native)` provider string and the new
//      `mlockBackend()` / `isMlockActive()` test cases.
//   3. Node 22 or Node 24 without the addon (path 3) — defensive no-op
//      with a single mlock-unavailable warn.

import { describe, expect, it, beforeEach, vi } from "vitest";
import { setPqcEmit, PQC_EVENT } from "../logging/pqc-log.js";
import type { LogLevel, PqcLogPayload } from "../logging/pqc-log.js";
import {
  isMlockActive,
  mlockKey,
  munlockKey,
  mlockBackend,
  protectKey,
  __resetMlockCacheForTests,
  MAX_MLOCK_BYTES,
} from "./mlock-helper.js";
import nativeAddon from "./native/mlock-addon.cjs";

interface CapturedEvent {
  level: LogLevel;
  event: string;
  payload: PqcLogPayload;
}

let captured: CapturedEvent[] = [];
beforeEach(() => {
  captured = [];
  __resetMlockCacheForTests();
  setPqcEmit((level, event, payload) => {
    captured.push({ level, event, payload });
  });
});

describe("mlock-helper (defensive path on Node 22)", () => {
  it("isMlockActive reports whether process.mlock or the native addon is available", () => {
    const v = isMlockActive();
    expect(typeof v).toBe("boolean");
  });

  it("mlockBackend returns process|native|null based on feature-detect", () => {
    const b = mlockBackend();
    expect(["process", "native", null]).toContain(b);
    if (b !== null) {
      expect(isMlockActive()).toBe(true);
    } else {
      expect(isMlockActive()).toBe(false);
    }
  });

  it("mlockKey on a 32-byte Buffer does not throw, regardless of Node version", () => {
    const buf = Buffer.alloc(32, 0xab);
    expect(() => mlockKey(buf, "test:32")).not.toThrow();
  });

  it("protectKey preserves bytes and zeroes the source when secure mapping is available", () => {
    const source = Buffer.alloc(32, 0xa5);
    const protectedKey = protectKey(source, "test:protect");
    expect(protectedKey).toEqual(Buffer.alloc(32, 0xa5));
    if (protectedKey !== source) {
      expect(source).toEqual(Buffer.alloc(32));
      const ok = captured.find(
        (event) =>
          event.event === PQC_EVENT.Mlock &&
          event.payload.provider === "test:protect (backend=native-secure-mapping)",
      );
      expect(ok?.payload.status).toBe("ok");
    }
    protectedKey.fill(0);
    munlockKey(protectedKey, "test:protect");
  });

  it("mlockKey is a no-op for empty Buffer", () => {
    const buf = Buffer.alloc(0);
    expect(() => mlockKey(buf, "test:empty")).not.toThrow();
  });

  it("mlockKey is a no-op for null / undefined", () => {
    expect(() => mlockKey(null, "test:null")).not.toThrow();
    expect(() => mlockKey(undefined, "test:undefined")).not.toThrow();
  });

  it("mlockKey emits a single mlock-unavailable warning on Node < 24.0.0 (or no addon)", () => {
    __resetMlockCacheForTests();
    const buf = Buffer.alloc(32, 0xab);
    mlockKey(buf, "test:first");
    mlockKey(buf, "test:second");
    mlockKey(buf, "test:third");

    if (!isMlockActive()) {
      const unavail = captured.filter((e) => e.event === PQC_EVENT.MlockUnavailable);
      expect(unavail.length).toBe(1);
      expect(unavail[0].level).toBe("warn");
      expect(unavail[0].payload.status).toBe("skipped");
      // 9/5 follow-up: the unavailable message should now also
      // mention the N-API fallback as a mitigation.
      expect(unavail[0].payload.detail).toMatch(/N-API|native/);
    }
  });

  it("mlockKey emits a mlock-ok debug event on Node 24+ (process or native backend)", () => {
    const buf = Buffer.alloc(32, 0xcd);
    mlockKey(buf, "test:ok");
    if (isMlockActive()) {
      const backend = mlockBackend();
      // After hardening the success log moved to debug level so the
      // [PQC] log is not flooded on every wrap/unwrap call.
      const ok = captured.filter((e) => e.event === PQC_EVENT.Mlock && e.payload.status === "ok");
      expect(ok.length).toBe(1);
      expect(ok[0].level).toBe("debug");
      expect(ok[0].payload.byteLength).toBe(32);
      // 9/5 follow-up: provider now includes the backend tag so
      // operators can tell at a glance which path won.
      expect(ok[0].payload.provider).toBe(`test:ok (backend=${backend})`);
      // Production log should include platform/arch context for debug.
      expect(ok[0].payload.detail).toMatch(/linux|darwin|win32/);
    } else {
      const ok = captured.filter((e) => e.event === PQC_EVENT.Mlock && e.payload.status === "ok");
      expect(ok.length).toBe(0);
    }
  });

  it("mlockKey refuses to mlock a buffer above MAX_MLOCK_BYTES (DoS guard)", () => {
    // 2 MiB — definitely not a wrap key, definitely a caller bug.
    const huge = Buffer.alloc(2 * 1024 * 1024);
    expect(() => mlockKey(huge, "test:huge")).not.toThrow();

    // On Node 24+ the refusal fires once per process; on Node 22
    // mlock is unavailable so no refusal is logged (the size guard
    // still runs but the warn fires only on Node 24+ where mlock
    // would have been called).
    if (isMlockActive()) {
      const refused = captured.filter(
        (e) => e.event === PQC_EVENT.Mlock && e.payload.status === "refused",
      );
      expect(refused.length).toBe(1);
      expect(refused[0].payload.byteLength).toBe(2 * 1024 * 1024);
      expect(refused[0].payload.detail).toContain("refusing");
      expect(refused[0].payload.detail).toContain("caller bug");
    }
  });

  it("oversize refusal is idempotent (warned once per process)", () => {
    if (!isMlockActive()) return; // No-op on Node 22, nothing to test.
    const huge1 = Buffer.alloc(2 * 1024 * 1024, 0xaa);
    const huge2 = Buffer.alloc(3 * 1024 * 1024, 0xbb);
    mlockKey(huge1, "test:huge1");
    mlockKey(huge2, "test:huge2");
    mlockKey(huge1, "test:huge1-again");
    const refused = captured.filter(
      (e) => e.event === PQC_EVENT.Mlock && e.payload.status === "refused",
    );
    expect(refused.length).toBe(1);
  });

  it("MAX_MLOCK_BYTES is 1 MiB (production wrap keys are 32-64 bytes)", () => {
    expect(MAX_MLOCK_BYTES).toBe(1024 * 1024);
  });

  it("mlockKey tolerates repeated calls on the same buffer", () => {
    // Linux page locks are not reference-counted per caller. This only asserts
    // that repeated defensive calls do not throw; it does not grant multiple
    // independent unlock leases for a shared page.
    const buf = Buffer.alloc(32, 0x42);
    expect(() => {
      mlockKey(buf, "test:idem-1");
      mlockKey(buf, "test:idem-2");
      mlockKey(buf, "test:idem-3");
    }).not.toThrow();
  });

  it("munlockKey is a no-op on empty / null / undefined", () => {
    expect(() => munlockKey(null, "test:null")).not.toThrow();
    expect(() => munlockKey(undefined, "test:undefined")).not.toThrow();
    expect(() => munlockKey(Buffer.alloc(0), "test:empty")).not.toThrow();
  });

  it("munlockKey does not throw on a real Buffer (idempotent)", () => {
    const buf = Buffer.alloc(32, 0xef);
    expect(() => munlockKey(buf, "test:munlock")).not.toThrow();
    expect(() => munlockKey(buf, "test:munlock-again")).not.toThrow();
  });

  it("__resetMlockCacheForTests allows re-running the feature-detect", () => {
    const before = isMlockActive();
    __resetMlockCacheForTests();
    const after = isMlockActive();
    expect(before).toBe(after);
  });
});

describe("mlock-helper N-API native addon (M6.B v2 path 2)", () => {
  // The native addon is built by `pnpm run build:native` (Linux
  // first cut; macOS / Windows deferred to audit-grade review).
  // These tests assume the addon has been built on the current host;
  // on a host where it has not, they no-op (the M6.B v2 path is
  // additive — the helper still works on the existing process or
  // no-op path).

  it("native secureCopy rejects allocations above the helper limit", () => {
    if (!nativeAddon.isAvailable()) {
      return;
    }
    const oversized = Buffer.alloc(MAX_MLOCK_BYTES + 1);
    expect(() => nativeAddon.secureCopySync(oversized)).toThrow(/exceeds 1 MiB limit/);
  });

  it("native backend emits a mlock-ok debug event with backend=native", () => {
    if (mlockBackend() !== "native") {
      // Addon not built on this host — skip; path is exercised on
      // the build machine.
      return;
    }
    const buf = Buffer.alloc(32, 0x55);
    mlockKey(buf, "test:native-mlock");
    const ok = captured.filter((e) => e.event === PQC_EVENT.Mlock && e.payload.status === "ok");
    expect(ok.length).toBe(1);
    expect(ok[0].payload.provider).toBe("test:native-mlock (backend=native)");
    expect(ok[0].payload.byteLength).toBe(32);
  });

  it("native munlock is a no-op on the helper side (success path)", () => {
    if (mlockBackend() !== "native") return;
    const buf = Buffer.alloc(32, 0x66);
    mlockKey(buf, "test:native-munlock");
    expect(() => munlockKey(buf, "test:native-munlock")).not.toThrow();
  });

  it("native mlock of an empty Buffer is a no-op (0-byte guard)", () => {
    // This guards the mlockKey early-return for empty input — the
    // native addon would also be a no-op (returns 0 for len==0),
    // but the helper should never reach it.
    if (mlockBackend() !== "native") return;
    const buf = Buffer.alloc(0);
    expect(() => mlockKey(buf, "test:native-empty")).not.toThrow();
    const ok = captured.filter((e) => e.event === PQC_EVENT.Mlock && e.payload.status === "ok");
    expect(ok.length).toBe(0);
  });

  it("fail-closed to no-op when native addon is not built (path 3)", () => {
    // Simulate "addon not built" by resetting the backend cache and
    // stubbing the wrapper. The helper must log the
    // mlock-unavailable warn once and silently no-op.
    __resetMlockCacheForTests();
    // We can't easily un-load the addon in-process, so this test
    // asserts the contract on Node 22 only — the helper will see
    // process.mlock === undefined AND nativeAddon.isAvailable() ===
    // false (because Node 22 doesn't ship process.mlock and the
    // addon is not built in CI). The defensive no-op path is
    // already covered above; this test pins the contract that
    // isMlockActive() === false.
    if (mlockBackend() !== null) {
      // If the addon is built on the host (this test environment),
      // skip — the path-2 tests above already exercise the active
      // path.
      return;
    }
    expect(isMlockActive()).toBe(false);
    const buf = Buffer.alloc(32, 0x77);
    expect(() => mlockKey(buf, "test:fail-closed")).not.toThrow();
    const unavail = captured.filter((e) => e.event === PQC_EVENT.MlockUnavailable);
    expect(unavail.length).toBe(1);
  });
});
