// Real process death and cold recovery of Doctor's legacy identity retirement.
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import { requireNodeSqlite } from "./node-sqlite.js";

const stages = [
  "receipt-recorded",
  "archive-created",
  "before-claim-remove",
  "archive-verified",
] as const;
type CrashStage = (typeof stages)[number] | "claim-published";
type Observation = {
  deviceId: string;
  wrappedSha256: string;
  removedSource: number;
  identityCount: number;
  receiptCount: number;
  schemaVersion: number;
};
type WorkerOutput = Observation & {
  stage: string;
  result?: { changes: string[]; warnings: string[] };
};

const workerSource = String.raw`
  import crypto from "node:crypto";
  import fs from "node:fs";
  import path from "node:path";
  import { DatabaseSync } from "node:sqlite";
  import { __setFsSafeTestHooksForTest } from "@openclaw/fs-safe/test-hooks";
  const stage = process.argv[1];
  const stateDir = process.env.OPENCLAW_STATE_DIR;
  const sourcePath = path.join(stateDir, "identity", "device.json");
  const archivePath = sourcePath + ".migrated";
  const claimPath = sourcePath + ".doctor-importing";
  function observe() {
    const db = new DatabaseSync(path.join(stateDir, "state", "openclaw.sqlite"), { readOnly: true });
    try {
      const row = db.prepare("SELECT device_id, mldsa_private_key_wrapped FROM device_identities WHERE identity_key='primary'").get();
      return {
        deviceId: row.device_id,
        wrappedSha256: crypto.createHash("sha256").update(row.mldsa_private_key_wrapped).digest("hex"),
        removedSource: db.prepare("SELECT removed_source AS value FROM migration_sources WHERE migration_kind='legacy-device-identity-json'").get().value,
        identityCount: db.prepare("SELECT COUNT(*) AS value FROM device_identities").get().value,
        receiptCount: db.prepare("SELECT COUNT(*) AS value FROM migration_sources").get().value,
        schemaVersion: db.prepare("PRAGMA user_version").get().user_version,
      };
    } finally {
      db.close();
    }
  }
  function interrupt() {
    fs.writeSync(1, JSON.stringify({ stage, ...observe() }) + "\n");
    process.kill(process.pid, "SIGKILL");
  }
  function interruptClaim() {
    fs.writeSync(1, JSON.stringify({ stage }) + "\n");
    process.kill(process.pid, "SIGKILL");
  }
  __setFsSafeTestHooksForTest({
    afterPublishTargetCreated(method, targetPath) {
      if (stage === "claim-published" && method === "hardlink" && targetPath === claimPath) interruptClaim();
    },
    beforeOpen(filePath) {
      if (stage === "archive-created" && filePath === archivePath && fs.existsSync(archivePath)) interrupt();
    },
    beforeRootFallbackMutation(operation, targetPath) {
      if (stage === "before-claim-remove" && operation === "remove" && targetPath === claimPath) interrupt();
    },
  });
  const { detectLegacyDeviceIdentity, migrateLegacyDeviceIdentity } = await import(process.env.PQC_CRASH_MIGRATION_MODULE);
  const result = await migrateLegacyDeviceIdentity({
    stateDir,
    env: process.env,
    doctorOnlyStateMigrations: true,
    detected: detectLegacyDeviceIdentity({ stateDir, env: process.env, doctorOnlyStateMigrations: true }),
    afterReceiptRecorded: stage === "receipt-recorded" ? interrupt : undefined,
    afterArchiveVerified: stage === "archive-verified" ? interrupt : undefined,
  });
  if (stage !== "recover") throw new Error("requested crash checkpoint was not reached: " + JSON.stringify(result));
  fs.writeSync(1, JSON.stringify({ stage, result, ...observe() }) + "\n");
  const { closeOpenClawStateDatabaseForTest } = await import(process.env.PQC_CRASH_DATABASE_MODULE);
  closeOpenClawStateDatabaseForTest();
`;

function worker(stateDir: string, stage: CrashStage | "recover") {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "--eval", workerSource, stage],
    {
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
      env: {
        PATH: process.env.PATH,
        HOME: stateDir,
        TMPDIR: stateDir,
        NODE_ENV: "test",
        OPENCLAW_STATE_DIR: stateDir,
        OPENCLAW_CONFIG_PATH: path.join(stateDir, "openclaw.json"),
        OPENCLAW_WRAP_KEY_FILE: path.join(stateDir, "wrap-key.b64"),
        OPENCLAW_WRAP_KEY_ID: "crash-test",
        PQC_CRASH_MIGRATION_MODULE: new URL(
          "./state-migrations.device-identity.ts",
          import.meta.url,
        ).href,
        PQC_CRASH_DATABASE_MODULE: new URL("../state/openclaw-state-db.ts", import.meta.url).href,
      },
      encoding: "utf8",
      timeout: 30_000,
      killSignal: "SIGKILL",
      maxBuffer: 1024 * 1024,
    },
  );
}

function output(result: ReturnType<typeof worker>): WorkerOutput {
  expect(result.error, result.stderr).toBeUndefined();
  const line = result.stdout.trim().split("\n").at(-1);
  expect(line, result.stderr).toBeTruthy();
  return JSON.parse(line!) as WorkerOutput;
}

function readPersistedIdentity(stateDir: string): Observation {
  const { DatabaseSync } = requireNodeSqlite();
  const db = new DatabaseSync(path.join(stateDir, "state", "openclaw.sqlite"), { readOnly: true });
  try {
    const row = db
      .prepare(
        "SELECT device_id, mldsa_private_key_wrapped FROM device_identities WHERE identity_key='primary'",
      )
      .get() as { device_id: string; mldsa_private_key_wrapped: Uint8Array };
    return {
      deviceId: row.device_id,
      wrappedSha256: crypto
        .createHash("sha256")
        .update(row.mldsa_private_key_wrapped)
        .digest("hex"),
      removedSource: (
        db
          .prepare(
            "SELECT removed_source AS value FROM migration_sources WHERE migration_kind='legacy-device-identity-json'",
          )
          .get() as { value: number }
      ).value,
      identityCount: (
        db.prepare("SELECT COUNT(*) AS value FROM device_identities").get() as { value: number }
      ).value,
      receiptCount: (
        db.prepare("SELECT COUNT(*) AS value FROM migration_sources").get() as { value: number }
      ).value,
      schemaVersion: (db.prepare("PRAGMA user_version").get() as { user_version: number })
        .user_version,
    };
  } finally {
    db.close();
  }
}

function prepareLegacyIdentity(stateDir: string): { source: Buffer; sourcePath: string } {
  fs.writeFileSync(
    path.join(stateDir, "wrap-key.b64"),
    Buffer.alloc(32, 27).toString("base64url"),
    { mode: 0o600 },
  );
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const source = Buffer.from(
    `${JSON.stringify({ version: 1, deviceId: "legacy-id", publicKeyPem: publicKey.export({ format: "pem", type: "spki" }), privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }), createdAtMs: 1_700_000_000_000, note: "旧身份字节保持不变" })}\n`,
  );
  const sourcePath = path.join(stateDir, "identity", "device.json");
  fs.mkdirSync(path.dirname(sourcePath));
  fs.writeFileSync(sourcePath, source, { mode: 0o600 });
  return { source, sourcePath };
}

it.skipIf(process.platform !== "linux")(
  "recovers a complete hardlinked claim after SIGKILL before source removal",
  async () => {
    await withTempDir("identity-claim-crash-", async (temporaryDir) => {
      const stateDir = fs.realpathSync(temporaryDir);
      const { source, sourcePath } = prepareLegacyIdentity(stateDir);
      const claimPath = `${sourcePath}.doctor-importing`;

      const killed = worker(stateDir, "claim-published");
      expect(killed.error, killed.stderr).toBeUndefined();
      expect(killed.signal, killed.stderr).toBe("SIGKILL");
      expect(killed.status).toBeNull();
      expect(output(killed).stage).toBe("claim-published");
      expect(fs.readFileSync(sourcePath)).toEqual(source);
      expect(fs.readFileSync(claimPath)).toEqual(source);
      expect(fs.statSync(sourcePath).ino).toBe(fs.statSync(claimPath).ino);
      expect(fs.statSync(sourcePath).nlink).toBe(2);

      const recovered = worker(stateDir, "recover");
      expect(recovered.status, recovered.stderr).toBe(0);
      const after = output(recovered);
      expect(after.result?.warnings).toEqual([]);
      expect(after.result?.changes.length).toBeGreaterThan(0);
      expect(after.removedSource).toBe(1);
      expect(fs.existsSync(sourcePath)).toBe(false);
      expect(fs.existsSync(claimPath)).toBe(false);
      expect(fs.readFileSync(`${sourcePath}.migrated`)).toEqual(source);
      expect(fs.statSync(`${sourcePath}.migrated`).mode & 0o777).toBe(0o600);

      const repeated = worker(stateDir, "recover");
      expect(repeated.status, repeated.stderr).toBe(0);
      expect(output(repeated).result).toEqual({ changes: [], warnings: [] });
    });
  },
);

it.skipIf(process.platform !== "linux").each(stages)(
  "recovers in a new process after SIGKILL at %s",
  async (stage) => {
    await withTempDir("identity-crash-", async (temporaryDir) => {
      const stateDir = fs.realpathSync(temporaryDir);
      const { source, sourcePath } = prepareLegacyIdentity(stateDir);

      const killed = worker(stateDir, stage);
      const interrupted = output(killed);
      expect(killed.signal, killed.stderr).toBe("SIGKILL");
      expect(killed.status).toBeNull();
      expect(interrupted.stage).toBe(stage);
      const before = readPersistedIdentity(stateDir);
      expect(interrupted).toMatchObject(before);
      expect(before).toMatchObject({
        removedSource: 0,
        identityCount: 1,
        receiptCount: 1,
        schemaVersion: 6,
      });
      expect(before.deviceId).toMatch(/^[a-f0-9]{64}$/);
      expect(fs.existsSync(sourcePath)).toBe(false);
      expect(fs.existsSync(`${sourcePath}.doctor-importing`)).toBe(stage !== "archive-verified");
      if (stage !== "archive-verified") {
        expect(fs.readFileSync(`${sourcePath}.doctor-importing`)).toEqual(source);
      }
      expect(fs.existsSync(`${sourcePath}.migrated`)).toBe(stage !== "receipt-recorded");
      if (stage !== "receipt-recorded") {
        expect(fs.readFileSync(`${sourcePath}.migrated`)).toEqual(source);
      }

      const recovered = worker(stateDir, "recover");
      expect(recovered.status, recovered.stderr).toBe(0);
      const after = output(recovered);
      expect(after.result?.warnings).toEqual([]);
      expect(after.result?.changes.length).toBeGreaterThan(0);
      expect(after).toMatchObject({ ...before, removedSource: 1 });
      expect(readPersistedIdentity(stateDir)).toEqual({ ...before, removedSource: 1 });
      expect(fs.existsSync(sourcePath)).toBe(false);
      expect(fs.existsSync(`${sourcePath}.doctor-importing`)).toBe(false);
      expect(fs.readFileSync(`${sourcePath}.migrated`)).toEqual(source);
      expect(fs.statSync(`${sourcePath}.migrated`).mode & 0o777).toBe(0o600);
      expect(
        fs
          .readdirSync(path.dirname(sourcePath))
          .filter((name) => name.startsWith("device.json.migrated")),
      ).toEqual(["device.json.migrated"]);

      const repeated = worker(stateDir, "recover");
      expect(repeated.status, repeated.stderr).toBe(0);
      const stable = output(repeated);
      expect(stable.result).toEqual({ changes: [], warnings: [] });
      expect(stable).toMatchObject({ ...before, removedSource: 1 });
    });
  },
);
