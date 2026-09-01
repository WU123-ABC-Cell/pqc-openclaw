// mlock-helper.test.ts — verify defensive behavior on Node 22 (no-op + warn once)
// and that the helper is a no-op on empty / non-Buffer inputs.
//
// (PQC whitepaper §6.3 v2, 2026-09-01 follow-up.)
//
// On Node 24.0.0+ the same tests would assert that process.mlock was
// called; on Node 22.23.1 (current) they assert the defensive path.

import { describe, expect, it, beforeEach, vi } from "vitest";
import {
  isMlockActive,
  mlockKey,
  munlockKey,
  __resetMlockCacheForTests,
} from "./mlock-helper.js";
import { setPqcEmit, PQC_EVENT } from "../logging/pqc-log.js";
import type { LogLevel, PqcLogPayload } from "../logging/pqc-log.js";

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
    // We do not assert the literal value (Node version dependent);
    // only that the call returns a boolean and does not throw.
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

    // On Node 22 the mlock-unavailable warning fires once (idempotent
    // across repeated calls). On Node 24+ the warning never fires and
    // an mlock-ok info event is emitted instead.
    if (!isMlockActive()) {
      const unavail = captured.filter((e) => e.event === PQC_EVENT.MlockUnavailable);
      expect(unavail.length).toBe(1);
      expect(unavail[0].level).toBe("warn");
      expect(unavail[0].payload.status).toBe("skipped");
    }
  });

  it("mlockKey emits a mlock-ok info event on Node 24+ (skipped on Node 22)", () => {
    const buf = Buffer.alloc(32, 0xcd);
    mlockKey(buf, "test:ok");
    if (isMlockActive()) {
      const ok = captured.filter((e) => e.event === PQC_EVENT.Mlock && e.payload.status === "ok");
      expect(ok.length).toBe(1);
      expect(ok[0].payload.byteLength).toBe(32);
      expect(ok[0].payload.provider).toBe("test:ok");
    } else {
      // On Node 22 we should have exactly the unavailability warning,
      // not an ok event.
      const ok = captured.filter((e) => e.event === PQC_EVENT.Mlock && e.payload.status === "ok");
      expect(ok.length).toBe(0);
    }
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
