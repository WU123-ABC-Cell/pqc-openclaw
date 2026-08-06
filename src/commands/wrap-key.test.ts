import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { resetDefaultWrappingProviderForTest } from "../infra/device-identity-store-keyring-default.js";
import { createDefaultKeyringProvider } from "../security/keyring-provider.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";
import { openOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { runWrapKeyCommand } from "./wrap-key.js";

let tmpDir: string;
let env: NodeJS.ProcessEnv;

beforeAll(() => {
  resetDefaultWrappingProviderForTest();
  tmpDir = mkdtempSync(join(tmpdir(), "openclaw-wrap-cmd-"));
  env = { OPENCLAW_STATE_DIR: tmpDir };
  // Apply all migrations to a fresh state.db
  const database = openOpenClawStateDatabase({ env });
  void database;
});

afterAll(() => {
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("runWrapKeyCommand dispatch", () => {
  it("returns USAGE with exitCode 0 when no subcommand", async () => {
    const r = await runWrapKeyCommand([], { env });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("Usage: openclaw wrap-key");
  });

  it("returns USAGE with --help", async () => {
    const r = await runWrapKeyCommand(["--help"]);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("export");
    expect(r.stdout).toContain("import");
    expect(r.stdout).toContain("rotate");
    expect(r.stdout).toContain("status");
  });

  it("returns exitCode 2 for unknown subcommand", async () => {
    const r = await runWrapKeyCommand(["bogus"], { env });
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("unknown subcommand: bogus");
  });
});

describe("runWrapKeyCommand status", () => {
  it("reports empty state when no device identities exist", async () => {
    const r = await runWrapKeyCommand(["status"], { env });
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toContain("total device identities:  0");
    expect(r.stdout).toContain("wrapped (PQC 2.2):       0");
  });
});

describe("runWrapKeyCommand export + import round-trip", () => {
  it("exports the active wrap key and re-imports it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "openclaw-wrap-roundtrip-"));
    try {
      // Provider scoped to this tmp dir
      const provider = createDefaultKeyringProvider({ dir, preferOSKeyring: false });
      const pw = "test-passphrase-roundtrip";
      const expRes = await runWrapKeyCommand(["export", "--passphrase", pw], {
        env,
        provider,
      });
      expect(expRes.exitCode).toBe(0);
      const blob = expRes.stdout.trim();
      expect(blob.length).toBeGreaterThan(0);

      // Import into a fresh dir (simulating disaster recovery)
      const dir2 = mkdtempSync(join(tmpdir(), "openclaw-wrap-restore-"));
      try {
        const provider2 = createDefaultKeyringProvider({ dir: dir2, preferOSKeyring: false });
        const impRes = await runWrapKeyCommand(["import", blob, "--passphrase", pw], {
          env,
          provider: provider2,
        });
        expect(impRes.exitCode).toBe(0);
        expect(impRes.stdout).toContain("imported wrap key");
      } finally {
        rmSync(dir2, { recursive: true, force: true });
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects an invalid backup blob with exitCode 2", async () => {
    const r = await runWrapKeyCommand(["import", "not-a-real-blob", "--passphrase", "pw"], { env });
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("invalid backup blob");
  });

  it("rejects missing blob argument with exitCode 2", async () => {
    const r = await runWrapKeyCommand(["import"], { env });
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("usage");
  });
});

describe("runWrapKeyCommand rotate", () => {
  it("refuses without --confirm (exitCode 2)", async () => {
    const r = await runWrapKeyCommand(["rotate"], { env });
    expect(r.exitCode).toBe(2);
    expect(r.stderr).toContain("refusing to rotate without --confirm");
  });
});
