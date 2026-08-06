import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { runWrapKeyHealthCheck, wrapKeyHealthCheck } from "./wrap-key-health-check.js";

function freshEmptyDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return dir;
}

function withFreshDir<T>(prefix: string, fn: (dir: string) => T): T {
  const dir = freshEmptyDir(prefix);
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("wrapKeyHealthCheck metadata", () => {
  it("has the right id, kind, defaultEnabled, and source", () => {
    expect(wrapKeyHealthCheck.id).toBe("core/doctor/wrap-key");
    expect(wrapKeyHealthCheck.kind).toBe("core");
    expect(wrapKeyHealthCheck.defaultEnabled).toBe(false);
    expect(wrapKeyHealthCheck.source).toBe("doctor");
    expect(typeof wrapKeyHealthCheck.description).toBe("string");
    expect(wrapKeyHealthCheck.description.length).toBeGreaterThan(0);
  });

  it("has a detect() function", () => {
    expect(typeof wrapKeyHealthCheck.detect).toBe("function");
  });
});

describe("runWrapKeyHealthCheck on missing state.db", () => {
  it("returns ok=false when state.db does not exist", async () => {
    await withFreshDir("openclaw-no-state-", async (dir) => {
      const result = await runWrapKeyHealthCheck({ env: { OPENCLAW_STATE_DIR: dir } });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(typeof result.error).toBe("string");
        expect(result.error.length).toBeGreaterThan(0);
      }
    });
  });

  it("returns ok=false when env has no OPENCLAW_STATE_DIR and no default", async () => {
    await withFreshDir("openclaw-bare-", async (dir) => {
      // Cwd is irrelevant; we just want to confirm the call doesn't crash.
      const result = await runWrapKeyHealthCheck({ env: { OPENCLAW_STATE_DIR: dir } });
      expect(result.ok).toBe(false);
    });
  });
});

describe("wrapKeyHealthCheck.detect() error path", () => {
  it("returns a single error finding when state.db is missing", async () => {
    await withFreshDir("openclaw-detect-", async (dir) => {
      const findings = await wrapKeyHealthCheck.detect({
        mode: "local" as any,
        runtime: {} as any,
        cfg: {} as any,
        env: { OPENCLAW_STATE_DIR: dir },
      });
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(1);
      expect(findings[0].checkId).toBe("core/doctor/wrap-key");
      expect(findings[0].severity).toBe("error");
      expect(findings[0].source).toBe("doctor");
      expect(typeof findings[0].message).toBe("string");
    });
  });
});
