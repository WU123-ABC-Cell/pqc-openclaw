// mlock-helper.test.ts — verify defensive behavior on Node 22 (no-op + warn once)
// and that the helper is a no-op on empty / non-Buffer inputs.
//
// (PQC whitepaper §6.3 v2, 2026-09-01 follow-up.)
//
// On Node 24.0.0+ the same tests would assert that process.mlock was
// called; on Node 22.23.1 (current) they assert the defensive path.

import { describe, expect, it, beforeEach, vi } from "vitest";
import { setPqcEmit, PQC_EVENT } from "../logging/pqc-log.js";
import type { LogLevel, PqcLogPayload } from "../logging/pqc-log.js";
import {
  isMlockActive,
  mlockKey,
  munlockKey,
  __resetMlockCacheForTests,
  MAX_MLOCK_BYTES,
} from "./mlock-helper.js";

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
  it("isMlockActive reports whether process.mlock is available", () => {
    const v = isMlockActive();
    expect(typeof v).toBe("boolean");
  });

  it("mlockKey on a 32-byte Buffer does not throw, regardless of Node version", () => {
    const buf = Buffer.alloc(32, 0xab);
    expect(() => mlockKey(buf, "test:32")).not.toThrow();
  });

  it("mlockKey is a no-op for empty Buffer", () => {
    const buf = Buffer.alloc(0);
    expect(() => mlockKey(buf, "test:empty")).not.toThrow();
  });

  it("mlockKey is a no-op for null / undefined", () => {
    expect(() => mlockKey(null, "test:null")).not.toThrow();
    expect(() => mlockKey(undefined, "test:undefined")).not.toThrow();
  });

  it("mlockKey emits a single mlock-unavailable warning on Node < 24.0.0", () => {
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
    }
  });

  it("mlockKey emits a mlock-ok debug event on Node 24+ (skipped on Node 22)", () => {
    const buf = Buffer.alloc(32, 0xcd);
    mlockKey(buf, "test:ok");
    if (isMlockActive()) {
      // After hardening the success log moved to debug level so the
      // [PQC] log is not flooded on every wrap/unwrap call.
      const ok = captured.filter((e) => e.event === PQC_EVENT.Mlock && e.payload.status === "ok");
      expect(ok.length).toBe(1);
      expect(ok[0].level).toBe("debug");
      expect(ok[0].payload.byteLength).toBe(32);
      expect(ok[0].payload.provider).toBe("test:ok");
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

  it("mlockKey is idempotent for repeated calls on the same buffer", () => {
    // The kernel reference-counts mlock on a page; calling mlock
    // twice on the same buffer should be safe (and a no-op the
    // second time). This test guards against accidental ref-count
    // bugs introduced in future refactors.
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
