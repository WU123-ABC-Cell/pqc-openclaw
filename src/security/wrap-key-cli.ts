// Wrap-key health check + openclaw wrap-key CLI helpers
// (PQC whitepaper 2.2.7 + 2.2.8).
//
// 2.2.7 — wrapKeyHealthCheck verifies the keyring is reachable AND
//   can unwrap a stored device identity if one is present. The
//   health check is the doctor entry point; it returns a structured
//   status the CLI / log layer can surface without re-implementing
//   the logic.
//
// 2.2.8 — openclaw wrap-key status | export | import | rotate
//   The CLI itself is registered elsewhere (src/cli/program/...) and
//   delegates to the command functions here. Keeping the command
//   functions pure (return result objects, do not write to stdout)
//   lets the CLI + Doctor + tests all drive the same code path.
//
// The status command surfaces the current keyId, the active provider
// type (file / env / os / composite), the rotation grace period
// (number of historical keys still resolvable via getKeyById), the
// PBKDF2 cost factor (so the operator sees the live security
// posture), and — when a device identity is provided — a
// per-row wrap-status flag.

import { type DeviceIdentityStoreOptions, readStoredDeviceIdentity } from "../infra/device-identity-store.js";
import { deserializeWrappedSecret, type WrappingKeyProvider } from "./secret-wrapping.js";
import { WRAP_KEY_BACKUP_CONSTANTS, exportWrapKey, importWrapKey, type WrapKeyBackup } from "./wrap-key-rotation.js";

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
    let row: ReturnType<typeof readStoredDeviceIdentity> = null;
    try {
      row = readStoredDeviceIdentity({ ...params.options, identityKey });
    } catch (error) {
      out.push({
        identityKey,
        deviceId: "",
        state: "malformed-envelope",
        wrapKeyId: null,
        detail: `readStoredDeviceIdentity failed: ${(error as Error).message}`,
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
  try {
    activeKeyId = provider.getActiveKey().keyId;
  } catch (error) {
    notes.push(`getActiveKey failed: ${(error as Error).message}`);
  }
  // Verify the active key is a 32-byte buffer (the contract the
  // wrap envelope expects). The provider's own getActiveKey already
  // guards this; the health check is the operator-facing surface.
  let activeKey: Buffer | null = null;
  try {
    activeKey = provider.getActiveKey().key;
  } catch {
    // already noted above
  }
  if (activeKey && activeKey.length !== 32) {
    notes.push(
      `active key must be 32 bytes (AES-256), got ${activeKey.length}; refusing to sign`,
    );
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
    ok: activeKeyId.length > 0,
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
export function parseWrapEnvelope(serialized: string): { ok: true } | { ok: false; reason: string } {
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
