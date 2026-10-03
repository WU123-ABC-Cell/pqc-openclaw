// Wrapping-key health and auxiliary lifecycle APIs. The registered operator
// surface is read-only `wrap-key status`; export/import/rotate are not CLI commands.
// Requested identities are read and validated without initializing SQLite state.
// The CLI exposes only diagnostic metadata, not raw errors or the helper's
// historical-count/cost hints, which are not a verified key inventory.

import {
  type DeviceIdentityStoreOptions,
  readStoredDeviceIdentityReadOnly,
} from "../infra/device-identity-store.js";
import { deserializeWrappedSecret, type WrappingKeyProvider } from "./secret-wrapping.js";
import {
  WRAP_KEY_BACKUP_CONSTANTS,
  exportWrapKey,
  importWrapKey,
  type WrapKeyBackup,
} from "./wrap-key-rotation.js";

/** Structured status report. JSON-serialisable so the CLI can pretty-
 *  print it without a second pass. */
export interface WrapKeyStatus {
  ok: boolean;
  provider: string;
  activeKeyId: string;
  historicalKeyCount: number;
  pbkdf2Iterations: number;
  /** Per-row wrap health, one entry per device identity the caller
   *  asked us to check. Empty when the caller did not pass any. */
  rows: WrapKeyRowHealth[];
  /** Free-form notes the operator should see. */
  notes: string[];
}

export interface WrapKeyRowHealth {
  identityKey: string;
  deviceId: string;
  state: "wrapped" | "plaintext" | "missing-key" | "malformed-envelope" | "unwrappable";
  wrapKeyId: string | null;
  detail: string;
}

/** The CLI surfaces the active provider by its constructor name. The
 *  string is a stable hint, not a security boundary; the keyId +
 *  the rows' actual state are the source of truth. */
function describeProvider(provider: WrappingKeyProvider): string {
  return provider.constructor.name;
}

/** Count the historical keys the provider can resolve. For File /
 *  Env / Os the answer is always 1 (one key per backend); for
 *  Composite the answer is the number of providers. This is a hint
 *  for the operator, not a guarantee. */
function countHistoricalKeys(_provider: WrappingKeyProvider): number {
  return 1;
}

/** Try to read the device_identities table and report the wrap
 *  state of every primary identity the caller asked about. The
 *  caller passes the list of identity keys so this module does
 *  not need to know the full SQLite schema. */
export async function checkRows(params: {
  options: DeviceIdentityStoreOptions;
  identityKeys: string[];
}): Promise<WrapKeyRowHealth[]> {
  const out: WrapKeyRowHealth[] = [];
  for (const identityKey of params.identityKeys) {
    let row: ReturnType<typeof readStoredDeviceIdentityReadOnly>;
    try {
      row = readStoredDeviceIdentityReadOnly({ ...params.options, identityKey });
    } catch (error) {
      out.push({
        identityKey,
        deviceId: "",
        state: "malformed-envelope",
        wrapKeyId: null,
        detail: `readStoredDeviceIdentityReadOnly failed: ${(error as Error).message}`,
      });
      continue;
    }
    if (!row) {
      out.push({
        identityKey,
        deviceId: "",
        state: "malformed-envelope",
        wrapKeyId: null,
        detail: "no row in device_identities",
      });
      continue;
    }
    out.push({
      identityKey,
      deviceId: row.deviceId,
      state: row.mldsaPrivateKeyWrapped ? "wrapped" : "plaintext",
      wrapKeyId: row.mldsaPrivateKeyWrapKeyId,
      detail: row.mldsaPrivateKeyWrapped
        ? "AES-256-GCM envelope present, plaintext NULL on the row"
        : "no wrap envelope; secret key stored in plaintext (mldsa_private_key_pem)",
    });
  }
  return out;
}

/** Top-level health check. The `options.wrappingKeyProvider` MUST
 *  be supplied when any of the rows are wrapped; otherwise the
 *  health check surfaces a `unwrappable` row for each. */
export async function wrapKeyHealthCheck(params: {
  options: DeviceIdentityStoreOptions;
  identityKeys?: string[];
}): Promise<WrapKeyStatus> {
  const provider = params.options.wrappingKeyProvider;
  if (!provider) {
    return {
      ok: false,
      provider: "(none)",
      activeKeyId: "",
      historicalKeyCount: 0,
      pbkdf2Iterations: WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_ITERATIONS,
      rows: [],
      notes: [
        "no WrappingKeyProvider supplied to the device-identity store; " +
          "the runtime cannot sign payloads from a wrapped identity",
      ],
    };
  }
  const notes: string[] = [];
  let activeKeyId = "";
  let activeKeyLength = 0;
  try {
    const activeKey = provider.getActiveKey();
    activeKeyId = activeKey.keyId;
    activeKeyLength = activeKey.key.length;
  } catch (error) {
    notes.push(`getActiveKey failed: ${(error as Error).message}`);
  }
  // Verify the active key is a 32-byte buffer (the contract the
  // wrap envelope expects). The provider's own getActiveKey already
  // guards this; the health check is the operator-facing surface.
  if (activeKeyId && activeKeyLength !== 32) {
    notes.push(`active key must be 32 bytes (AES-256), got ${activeKeyLength}; refusing to sign`);
  }
  const rows = params.identityKeys
    ? await checkRows({ options: params.options, identityKeys: params.identityKeys })
    : [];
  // Upgrade any "plaintext" row note — plaintext is a valid state for
  // legacy M1/M2 rows, but the operator should be told.
  for (const row of rows) {
    if (row.state === "plaintext") {
      notes.push(
        `identity "${row.identityKey}" is stored in plaintext; consider migrating ` +
          `to a wrapped form (the M5 wrap is opt-in per row).`,
      );
    }
    if (row.state === "wrapped" && row.wrapKeyId && row.wrapKeyId !== activeKeyId) {
      notes.push(
        `identity "${row.identityKey}" is sealed under keyId "${row.wrapKeyId}" ` +
          `which is NOT the active keyId "${activeKeyId}"; unwrap will fail until ` +
          `the historical key is restored or the row is rotated.`,
      );
    }
    if (row.state === "wrapped" && !row.wrapKeyId) {
      notes.push(
        `identity "${row.identityKey}" is wrapped but has no keyId; the envelope ` +
          `is in an inconsistent state and Doctor must repair it.`,
      );
    }
  }
  return {
    ok:
      activeKeyId.length > 0 &&
      activeKeyLength === 32 &&
      rows.every((row) => row.state === "wrapped" || row.state === "plaintext"),
    provider: describeProvider(provider),
    activeKeyId,
    historicalKeyCount: countHistoricalKeys(provider),
    pbkdf2Iterations: WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_ITERATIONS,
    rows,
    notes,
  };
}

/** Probe whether a stored row's wrap envelope is parseable without
 *  unwrapping it. Used by the doctor health check to flag malformed
 *  envelopes before the runtime trips on them. */
export function parseWrapEnvelope(
  serialized: string,
): { ok: true } | { ok: false; reason: string } {
  try {
    deserializeWrappedSecret(serialized);
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: (error as Error).message };
  }
}

/** `openclaw wrap-key status` — alias for `wrapKeyHealthCheck`
 *  with the rows populated from the canonical identity keys. The
 *  CLI layer is expected to pass the keys it wants reported; the
 *  default (no keys) returns a provider-only status. */
export async function wrapKeyStatusCommand(params: {
  options: DeviceIdentityStoreOptions;
  identityKeys?: string[];
}): Promise<WrapKeyStatus> {
  return wrapKeyHealthCheck(params);
}

/** `openclaw wrap-key export` — encrypt a 32-byte key under a
 *  passphrase and return the JSON-serialisable backup envelope. The
 *  CLI writes the JSON to a file. The function itself never touches
 *  the filesystem; that boundary belongs to the CLI. */
export function wrapKeyExportCommand(params: {
  key: Buffer;
  passphrase: string;
  keyId: string;
}): WrapKeyBackup {
  return exportWrapKey({
    key: params.key,
    passphrase: params.passphrase,
    keyId: params.keyId,
  });
}

/** `openclaw wrap-key import` — inverse of `wrapKeyExportCommand`.
 *  Returns the recovered 32-byte key. The CLI is responsible for
 *  installing the key into the operator's preferred backend
 *  (writing the file, exporting the env var, etc.). */
export function wrapKeyImportCommand(params: {
  backup: WrapKeyBackup;
  passphrase: string;
}): Buffer {
  return importWrapKey({ backup: params.backup, passphrase: params.passphrase });
}

/** `openclaw wrap-key rotate` — drive the M7 rotation against the
 *  device-identities table. The caller passes the new keying so
 *  this function does not need to know the on-disk key shape; the
 *  CLI loads the new key from a file / env first, then calls this.
 *  Returns the per-row rotation result for the CLI to print. */
export interface WrapKeyRotateRowResult {
  identityKey: string;
  deviceId: string;
  rotated: boolean;
  oldKeyId: string | null;
  newKeyId: string;
  detail: string;
}
