// PQC fork M8: wrap-key health check + openclaw wrap-key CLI helpers.
//   2.2.7 — wrapKeyHealthCheck surfaces a JSON-friendly status.
//   2.2.8 — wrapKeyStatusCommand / wrapKeyExportCommand /
//           wrapKeyImportCommand are the function-side surface for
//           the CLI; the actual CLI registration is out of scope for
//           this milestone.
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  PRIMARY_DEVICE_IDENTITY_KEY,
  readStoredDeviceIdentity,
  type DeviceIdentityStoreOptions,
} from "../infra/device-identity-store.js";
import {
  encodeMlDsa65SecretKey,
  generateMlDsa65KeyPair,
  encodeMlDsa65PublicKey,
  fingerprintMlDsa65PublicKey,
} from "../infra/mldsa65-key-storage.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { FileKeyring } from "./keyring-provider.js";
import {
  type ActiveWrappingKey,
  type WrappingKeyProvider,
  serializeWrappedSecret,
  wrapSecret,
} from "./secret-wrapping.js";
import {
  type WrapKeyStatus,
  parseWrapEnvelope,
  wrapKeyExportCommand,
  wrapKeyHealthCheck,
  wrapKeyImportCommand,
  wrapKeyStatusCommand,
} from "./wrap-key-cli.js";
import { WRAP_KEY_BACKUP_CONSTANTS } from "./wrap-key-rotation.js";

class InMemoryKeyring implements WrappingKeyProvider {
  private readonly activeId: string;
  private readonly keys = new Map<string, Buffer>();

  constructor(activeId: string) {
    this.activeId = activeId;
  }

  addKey(keyId: string, key: Buffer): void {
    this.keys.set(keyId, Buffer.from(key));
  }

  getActiveKey(): ActiveWrappingKey {
    const key = this.keys.get(this.activeId);
    if (!key) {
      throw new Error(`InMemoryKeyring: active key missing: ${this.activeId}`);
    }
    return { key, keyId: this.activeId };
  }

  getKeyById(keyId: string): Buffer | null {
    const key = this.keys.get(keyId);
    return key ? Buffer.from(key) : null;
  }
}

const tempDirs: string[] = [];
const originalKeys: Buffer[] = [];

function makeStoreOptions(wrappingKeyProvider?: WrappingKeyProvider): DeviceIdentityStoreOptions & {
  stateDir: string;
} {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m8-"));
  tempDirs.push(stateDir);
  return {
    stateDir,
    env: { ...process.env, OPENCLAW_STATE_DIR: stateDir },
    ...(wrappingKeyProvider ? { wrappingKeyProvider } : {}),
  };
}

function newKey(): Buffer {
  const k = randomBytes(32);
  originalKeys.push(k);
  return k;
}

beforeEach(() => {
  while (tempDirs.length > 0) tempDirs.pop();
  while (originalKeys.length > 0) originalKeys.pop();
});

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (!dir) continue;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }
  while (originalKeys.length > 0) {
    originalKeys.pop()?.fill(0);
  }
});

describe("wrapKeyHealthCheck (whitepaper 2.2.7)", () => {
  it("reports a missing keyring with a clear note", async () => {
    const options = makeStoreOptions();
    const status = await wrapKeyHealthCheck({ options });
    expect(status.ok).toBe(false);
    expect(status.activeKeyId).toBe("");
    expect(status.notes.some((n) => /no WrappingKeyProvider/.test(n))).toBe(true);
  });

  it("reports a healthy keyring with the live keyId and PBKDF2 cost", async () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    const status = await wrapKeyHealthCheck({ options });
    expect(status.ok).toBe(true);
    expect(status.activeKeyId).toBe("wrap-key-2026-08");
    expect(status.provider).toBe("InMemoryKeyring");
    expect(status.pbkdf2Iterations).toBe(WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_ITERATIONS);
  });

  it("flags a wrapped row sealed under a non-active keyId", async () => {
    // Insert a row under key "wrap-key-2026-08" with a keyring, then
    // construct a fresh keyring with a different active keyId. The
    // row is still sealed under the old keyId; the health check must
    // surface that. The keyring keeps the historical keyId's bytes
    // so the unwrap succeeds — we are testing the "active key
    // changed, but the historical key is still in the keyring"
    // state (M7's rotation grace period).
    const oldKey = newKey();
    const newKeyBuf = newKey();
    const keyringA = new InMemoryKeyring("wrap-key-2026-08");
    keyringA.addKey("wrap-key-2026-08", oldKey);
    const options = makeStoreOptions(keyringA);
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, keyringA);
    insertStoredDeviceIdentityIfAbsent(candidate, options);

    const keyringB = new InMemoryKeyring("wrap-key-2026-09");
    keyringB.addKey("wrap-key-2026-09", newKeyBuf);
    // Historical: the SAME key bytes that sealed the original row,
    // under the original keyId. Active is now "wrap-key-2026-09".
    keyringB.addKey("wrap-key-2026-08", oldKey);
    const readOptions: DeviceIdentityStoreOptions = {
      env: options.env,
      path: path.join(options.stateDir, "state", "openclaw.sqlite"),
      wrappingKeyProvider: keyringB,
    };
    const status = await wrapKeyHealthCheck({
      options: readOptions,
      identityKeys: [PRIMARY_DEVICE_IDENTITY_KEY],
    });
    expect(status.ok).toBe(true);
    expect(status.activeKeyId).toBe("wrap-key-2026-09");
    const row = status.rows[0];
    expect(row.state).toBe("wrapped");
    expect(row.wrapKeyId).toBe("wrap-key-2026-08");
    expect(status.notes.some((n) => /is NOT the active keyId/.test(n))).toBe(true);
  });

  it("flags a plaintext row (legacy M1/M2) as a hint, not an error", async () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    // Insert a plaintext row (no keyring on the insert path).
    const candidate = generateStoredDeviceIdentity(1_700_000_000_000, undefined, {
      allowPlaintextPrivateKey: true,
    });
    insertStoredDeviceIdentityIfAbsent(candidate, {
      env: options.env,
      path: path.join(options.stateDir, "state", "openclaw.sqlite"),
    });
    const status = await wrapKeyHealthCheck({
      options: { ...options, wrappingKeyProvider: keyring },
      identityKeys: [PRIMARY_DEVICE_IDENTITY_KEY],
    });
    const row = status.rows[0];
    expect(row.state).toBe("plaintext");
    expect(status.notes.some((n) => /plaintext; consider migrating/.test(n))).toBe(true);
  });

  it("returns an empty rows array when the caller does not list identity keys", async () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    const status = await wrapKeyHealthCheck({ options });
    expect(status.rows).toEqual([]);
  });
});

describe("wrapKeyStatusCommand (whitepaper 2.2.8)", () => {
  it("is a thin alias for wrapKeyHealthCheck", async () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const options = makeStoreOptions(keyring);
    const a: WrapKeyStatus = await wrapKeyHealthCheck({ options });
    const b: WrapKeyStatus = await wrapKeyStatusCommand({ options });
    expect(a.activeKeyId).toBe(b.activeKeyId);
    expect(a.provider).toBe(b.provider);
  });
});

describe("wrapKeyExportCommand / wrapKeyImportCommand (whitepaper 2.2.8)", () => {
  it("round-trips a 32-byte key under a passphrase through the CLI surface", () => {
    const key = newKey();
    const backup = wrapKeyExportCommand({
      key,
      passphrase: "the operator's secret",
      keyId: "wrap-key-2026-08",
    });
    expect(backup.version).toBe(1);
    expect(backup.keyId).toBe("wrap-key-2026-08");
    const recovered = wrapKeyImportCommand({
      backup,
      passphrase: "the operator's secret",
    });
    expect(recovered.equals(key)).toBe(true);
  });

  it("rejects the wrong passphrase", () => {
    const key = newKey();
    const backup = wrapKeyExportCommand({
      key,
      passphrase: "right",
      keyId: "wrap-key-2026-08",
    });
    expect(() => wrapKeyImportCommand({ backup, passphrase: "wrong" })).toThrow();
  });

  it("rejects a wrong-size key on export", () => {
    expect(() =>
      wrapKeyExportCommand({ key: Buffer.alloc(16), passphrase: "x", keyId: "k" }),
    ).toThrow(/32-byte/);
  });
});

describe("parseWrapEnvelope (envelope probe)", () => {
  it("accepts a freshly-wrapped envelope", () => {
    const keyring = new InMemoryKeyring("wrap-key-2026-08");
    keyring.addKey("wrap-key-2026-08", newKey());
    const wrapped = wrapSecret(Buffer.from("hello"), keyring);
    const serialized = serializeWrappedSecret(wrapped);
    const result = parseWrapEnvelope(serialized);
    expect(result.ok).toBe(true);
  });

  it("rejects a malformed envelope", () => {
    const result = parseWrapEnvelope("not base64url @@@");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toMatch(/malformed|non-empty/);
    }
  });

  it("rejects a base64url payload that is not JSON", () => {
    const notJson = Buffer.from("not json", "utf8").toString("base64url");
    const result = parseWrapEnvelope(notJson);
    expect(result.ok).toBe(false);
  });
});

describe("FileKeyring + CLI surface (cross-module integration)", () => {
  it("survives a full status flow through the FileKeyring backend", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-pqc-m8-file-"));
    tempDirs.push(dir);
    const keyPath = path.join(dir, "wrap.key");
    const key = newKey();
    // Buffer.from(buffer) clones the bytes; safe to base64url-encode.
    fs.writeFileSync(keyPath, Buffer.from(key).toString("base64url"));
    if (process.platform !== "win32") {
      fs.chmodSync(keyPath, 0o600);
    }
    const ring = new FileKeyring(keyPath, "wrap-key-2026-08");
    // Status with no wrappingKeyProvider surfaces a clear note.
    const bareStatus = await wrapKeyHealthCheck({
      options: { env: process.env },
    });
    expect(bareStatus.notes.length).toBeGreaterThan(0);
    // Re-run with the FileKeyring supplied.
    const fullStatus = await wrapKeyHealthCheck({
      options: { env: process.env, wrappingKeyProvider: ring },
    });
    expect(fullStatus.activeKeyId).toBe("wrap-key-2026-08");
    expect(fullStatus.provider).toBe("FileKeyring");
  });
});
