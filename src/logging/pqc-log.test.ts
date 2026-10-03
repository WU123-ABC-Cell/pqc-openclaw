import fs from "node:fs";
import os from "node:os";
import path from "node:path";
// PQC fork M9: structured [PQC] log markers (whitepaper 2.2.9).
//
// The PQC log surface is an indirection over a single `PqcEmit`
// function. Tests swap the emit for an in-memory recorder so we can
// assert the exact (level, event, payload) shape without touching
// the openclaw logger. The default sink is also exercised through
// the real canonical file transport below.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushLogger, resetLogger, setLoggerOverride, testApi } from "./logger.js";
import { getPqcEmit, PQC_EVENT, pqcLog, type PqcEmit, setPqcEmit } from "./pqc-log.js";
import { loggingState } from "./state.js";

interface CapturedEntry {
  level: Parameters<PqcEmit>[0];
  event: string;
  payload: Record<string, unknown>;
}

const captured: CapturedEntry[] = [];
const recorder: PqcEmit = (level, event, payload) => {
  captured.push({
    level,
    event,
    payload: { ...payload },
  });
};

beforeEach(() => {
  captured.length = 0;
  setPqcEmit(recorder);
});

afterEach(() => {
  setPqcEmit(null);
  testApi.resetFileLogTransportForTests();
  resetLogger();
});

describe("pqcLog (M9 structured log surface)", () => {
  it("routes an info call through the bound emit", () => {
    pqcLog.info(PQC_EVENT.WrapSecret, { keyId: "wrap-key-2026-08", byteLength: 4032 });
    expect(captured).toEqual([
      {
        level: "info",
        event: PQC_EVENT.WrapSecret,
        payload: { keyId: "wrap-key-2026-08", byteLength: 4032 },
      },
    ]);
  });

  it("routes warn / error / debug to the right level", () => {
    pqcLog.warn(PQC_EVENT.Keyring, { provider: "file" });
    pqcLog.error(PQC_EVENT.UnwrapSecret, { status: "fail", detail: "GCM auth" });
    pqcLog.debug(PQC_EVENT.Doctor, { detail: "rotation grace expired" });
    expect(captured.map((c) => c.level)).toEqual(["warn", "error", "debug"]);
  });

  it("passes through the canonical event ids from PQC_EVENT", () => {
    for (const event of Object.values(PQC_EVENT)) {
      captured.length = 0;
      pqcLog.info(event);
      expect(captured.map((entry) => entry.event)).toEqual([event]);
    }
  });

  it("strips undefined values from the payload", () => {
    pqcLog.info(PQC_EVENT.WrapKey, {
      keyId: "wrap-key-2026-08",
      detail: undefined,
    });
    expect(captured.map((entry) => entry.payload)).toEqual([{ keyId: "wrap-key-2026-08" }]);
  });

  it("refuses Buffer / TypedArray values in the payload", () => {
    const payload = {
      keyId: "wrap-key-2026-08",
      rawKey: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
    };
    pqcLog.info(PQC_EVENT.WrapSecret, payload);
    expect(captured.map((entry) => entry.payload)).toEqual([{ keyId: "wrap-key-2026-08" }]);
  });

  it("refuses to log fields whose name looks like a secret", () => {
    const payload = {
      keyId: "wrap-key-2026-08",
      passphrase: "the operator's secret",
      rawKeyMaterial: "anything",
      privateKey: "should not appear",
    };
    pqcLog.info(PQC_EVENT.Backup, payload);
    expect(captured.map((entry) => entry.payload)).toEqual([{ keyId: "wrap-key-2026-08" }]);
  });

  it("rebind to a different emit (the Doctor path)", () => {
    const other: CapturedEntry[] = [];
    setPqcEmit((level, event, payload) => {
      other.push({ level, event, payload: { ...payload } });
    });
    pqcLog.warn(PQC_EVENT.Doctor, { detail: "keyring missing" });
    expect(other).toEqual([
      { level: "warn", event: PQC_EVENT.Doctor, payload: { detail: "keyring missing" } },
    ]);
    // The previous recorder did not see the new event.
    expect(captured).toEqual([]);
  });

  it("setPqcEmit(null) restores the canonical sink", () => {
    setPqcEmit(null);
    expect(getPqcEmit()).not.toBe(recorder);
  });

  it("persists redacted events with canonical levels without writing command output", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-log-"));
    const file = path.join(dir, "events.jsonl");
    const previous = loggingState.forceConsoleToStderr;
    const stdout = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    try {
      setPqcEmit(null);
      setLoggerOverride({ level: "info", file });
      loggingState.forceConsoleToStderr = true;
      pqcLog.debug(PQC_EVENT.Mlock, { status: "ok", byteLength: 32 });
      const payload = {
        status: "ok" as const,
        detail: "Bearer sk-proj-abcdefghijklmnopqrstuvwxyz1234567890",
        rawKey: Buffer.from("do-not-log"),
        passphrase: "do-not-log",
      };
      pqcLog.info(PQC_EVENT.WrapSecret, payload);
      loggingState.forceConsoleToStderr = false;
      getPqcEmit()("fatal", PQC_EVENT.Doctor, { status: "fail" });
      getPqcEmit()("silent", PQC_EVENT.Doctor, {});
      await flushLogger();
      const text = fs.readFileSync(file, "utf8");
      const records = text
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(records.map((record) => record._meta.logLevelName)).toEqual(["INFO", "FATAL"]);
      expect(records.map((record) => record[1].event)).toEqual([
        PQC_EVENT.WrapSecret,
        PQC_EVENT.Doctor,
      ]);
      expect(records[0][1]).toMatchObject({ status: "ok" });
      expect(text).toContain("[PQC] wrap-secret");
      expect(text).not.toContain("do-not-log");
      expect(text).not.toContain("abcdefghijklmnopqrstuvwxyz1234567890");
      setLoggerOverride({ level: "silent", file });
      pqcLog.error(PQC_EVENT.Keyring, { status: "fail" });
      await flushLogger();
      expect(fs.readFileSync(file, "utf8")).toBe(text);
      expect(stdout).not.toHaveBeenCalled();
      expect(stderr).not.toHaveBeenCalled();
    } finally {
      loggingState.forceConsoleToStderr = previous;
      stdout.mockRestore();
      stderr.mockRestore();
      testApi.resetFileLogTransportForTests();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
