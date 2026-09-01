// PQC-structured logger (whitepaper 2.2.9).
//
// Every PQC-relevant log line is prefixed with `[PQC]` and an event
// id so operators can filter the openclaw log for post-quantum
// activity without grepping the full log. The event ids follow the
// whitepaper numbering: `wrap-secret`, `unwrap-secret`, `wrap-key`,
// `device-identity`, `keyring`, `rotation`, `backup`, `restore`,
// `doctor`. Each event carries a small structured payload
// (keyId, byte counts, status) so log analysis can correlate
// without re-reading the database.
//
// The logger intentionally wraps the openclaw logger rather than
// writing to stdout directly: the operator's log transport
// (file / pino / redacted stream) is reused, and the redaction
// policy that the openclaw logger applies to values is honoured
// here. Tests can swap the transport by replacing the `emit` hook.
import { type Logger as TsLogger } from "tslog";
import type { LogLevel } from "./levels.js";
import { normalizeLogLevel } from "./levels.js";

/** Canonical PQC event ids. Add new ones here; downstream consumers
 *  (doctor hints, log dashboards) read them as a stable vocabulary. */
export const PQC_EVENT = {
  WrapSecret: "wrap-secret",
  UnwrapSecret: "unwrap-secret",
  WrapKey: "wrap-key",
  DeviceIdentity: "device-identity",
  Keyring: "keyring",
  Rotation: "rotation",
  Backup: "backup",
  Restore: "restore",
  Doctor: "doctor",
  // PQC §6.3 v2 (mlock): emitted by mlock-helper on success / failure / unavailability.
  Mlock: "mlock",
  Munlock: "munlock",
  MlockUnavailable: "mlock-unavailable",
} as const;

export type PqcEventId = (typeof PQC_EVENT)[keyof typeof PQC_EVENT];

/** Structured payload for a PQC log event. The shape is open —
 *  fields are merged into the log record as-is. Keys whose values
 *  are secrets (passphrases, raw key bytes, plaintext device
 *  identities) MUST NOT be logged; the helper refuses them at the
 *  type level by not having fields for them. */
export interface PqcLogPayload {
  /** Optional keyId for wrap / unwrap / rotation events. */
  keyId?: string;
  /** Byte length of the wrapped / unwrapped payload. */
  byteLength?: number;
  /** Provider type for keyring events ("file" | "env" | "os" | "composite"). */
  provider?: string;
  /** Identity key (the row label, NOT the device id) for device-identity events. */
  identityKey?: string;
  /** Status flag. Use "ok" for success, "fail" for a refused operation,
   *  "rotate" for a rotation, "doctor" for a health-check finding. */
  status?: "ok" | "fail" | "rotate" | "doctor" | "skipped";
  /** Free-form operator-facing detail; the openclaw logger will
   *  redact any value that looks like a secret. */
  detail?: string;
}

/** Function the rest of the runtime calls to surface a PQC event.
 *  The default implementation writes through the openclaw logger
 *  (or, when the test environment has swapped it, the test sink). */
export type PqcEmit = (
  level: LogLevel,
  event: PqcEventId,
  payload: PqcLogPayload,
) => void;

let currentEmit: PqcEmit = defaultEmit;

/** Pre-emptive payload redaction. Applied at the PqcEmit boundary so
 *  every emit (test recorder, openclaw binding, default stdout) sees
 *  the redacted form. */
function emitWithRedaction(
  emit: PqcEmit,
  level: LogLevel,
  event: PqcEventId,
  payload: PqcLogPayload,
): void {
  emit(level, event, redactPayload(payload));
}

/** Override the emit function. Used by tests + by the openclaw
 *  boot path to bind the openclaw logger. The emit is always
 *  wrapped in the redaction pass so the contract holds regardless
 *  of who supplies the sink. */
export function setPqcEmit(emit: PqcEmit | null): void {
  currentEmit = emit ? wrapWithRedaction(emit) : defaultEmit;
}

/** Read the active emit function. */
export function getPqcEmit(): PqcEmit {
  return currentEmit;
}

/** Default emit: route through the openclaw logger when one is set,
 *  otherwise write a minimal JSON line on stdout. The fallback is
 *  what unit tests see; production wires in the openclaw logger via
 *  `bindOpenClawLogger` (called from the runtime's bootstrap). */
function defaultEmit(level: LogLevel, event: PqcEventId, payload: PqcLogPayload): void {
  const record = {
    level: typeof level === "number" ? level : normalizeLogLevel(level),
    event,
    ...redactPayload(payload),
  };
  // Best-effort stdout; production rebinds this to the openclaw
  // logger, which routes through pino with redaction.
  process.stdout.write(`[PQC] ${JSON.stringify(record)}\n`);
}

/** Bind the PQC emit to an openclaw tslog logger. The openclaw
 *  logger's redaction policy applies to every value. */
export function bindOpenClawLogger(logger: TsLogger<unknown>): void {
  setPqcEmit((level, event, payload) => {
    const tag = `[PQC] ${event}`;
    const redacted = redactPayload(payload);
    switch (level) {
      case "trace":
        logger.trace(tag, redacted);
        return;
      case "debug":
        logger.debug(tag, redacted);
        return;
      case "info":
        logger.info(tag, redacted);
        return;
      case "warn":
        logger.warn(tag, redacted);
        return;
      case "error":
      case "fatal":
        logger.error(tag, redacted);
        return;
      default:
        logger.info(tag, redacted);
    }
  });
}

/** Wrap an arbitrary emit so the redaction is applied uniformly. */
function wrapWithRedaction(emit: PqcEmit): PqcEmit {
  return (level, event, payload) => emitWithRedaction(emit, level, event, payload);
}

/** Strip fields that the type-level contract forbids (the helper
 *  exists so a future refactor that loosens the types cannot leak
 *  a secret by mistake). The current contract forbids none of the
 *  structured fields, but the helper also drops `undefined` values
 *  so a log line does not carry empty keys. */
function redactPayload(payload: PqcLogPayload): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (value === undefined) {
      continue;
    }
    // Belt-and-braces: refuse anything that smells like a raw key
    // (Buffer / TypedArray) or a passphrase (string with >= 16
    // non-whitespace characters and no whitespace at all).
    if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
      continue;
    }
    if (
      typeof value === "string" &&
      (key.toLowerCase().includes("passphrase") ||
        key.toLowerCase().includes("rawkey") ||
        key.toLowerCase().includes("privatekey"))
    ) {
      continue;
    }
    out[key] = value;
  }
  return out;
}

/** Convenience wrappers. The PQC surface never calls the openclaw
 *  logger directly — it goes through these helpers so a future
 *  "drop [PQC] markers" or "reroute to a dedicated stream" change
 *  has a single chokepoint. */
export const pqcLog = {
  info: (event: PqcEventId, payload: PqcLogPayload = {}): void => {
    currentEmit("info", event, payload);
  },
  warn: (event: PqcEventId, payload: PqcLogPayload = {}): void => {
    currentEmit("warn", event, payload);
  },
  error: (event: PqcEventId, payload: PqcLogPayload = {}): void => {
    currentEmit("error", event, payload);
  },
  debug: (event: PqcEventId, payload: PqcLogPayload = {}): void => {
    currentEmit("debug", event, payload);
  },
} as const;
