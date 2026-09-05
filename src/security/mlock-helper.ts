// mlock-helper.ts — defensive mlock for in-memory secret material
// (PQC whitepaper §6.3 v2, M6.B OsKeyring 真部署 100% follow-up, 9/1/2026,
// N-API native addon fallback 9/5/2026).
//
// Why this exists: the wrap key is loaded into process RAM at fork
// startup (via `OsKeyring.getActiveKey()` or `FileKeyring.readKey()`).
// The key sits in heap memory until the process exits. If the process
// is core-dumped (SIGSEGV / OOM) the wrap key lands in the dump
// file, where an attacker with disk access can read it. The 8/19
// `f89f296687` M12 v3 commit added `secure_memzero` for short-term
// use, but a long-lived wrap-key buffer in a 6-9s lifetime fork is
// still exposed.
//
// mlock(2) tells the kernel to keep a buffer in physical RAM (never
// swap to disk) and to exclude the pages from core dumps (when
// `RLIMIT_CORE` is set or when the kernel is configured with
// `coredump_filter` that respects `VM_DONTDUMP`).
//
// Three runtime paths, in priority order:
//   1. `process.mlock` / `process.munlock` stable (Node >= 24.0.0
//      stable). Verified for Node 24.15.0 on 2026-09-04 — NOT present
//      in that build (the API was reverted/removed before 24.x
//      shipped). On future Node 24.x / 25.x+ builds where the API
//      returns, this path wins without code changes.
//   2. N-API native addon (./native/mlock-addon) that calls
//      `mlock(2)` directly. Linux-only first cut. Built via
//      `pnpm run build:native`. Used when `process.mlock` is missing
//      but the operator has compiled the addon. This is the
//      M6.B v2 path documented in the PQC whitepaper §6.3 v2.
//   3. Defensive no-op with a single [PQC] mlock-unavailable warn
//      per process. Behavior preserved across Node versions and
//      builds, so production never throws from the wrap/unwrap path.
//
// This is defense-in-depth, not a hard guarantee: even with mlock
// active, an attacker with root on the host can read process memory.
// The point is to raise the bar against passive attacks (cold-boot,
// disk image after theft, kernel-privileged attacker without ptrace).
import { pqcLog, PQC_EVENT, type PqcLogPayload } from "../logging/pqc-log.js";
// eslint-disable-next-line @typescript-eslint/no-require-imports
import nativeAddon from "./native/mlock-addon.cjs";

/** Node version where process.mlock became stable (24.0.0). */
const MLOCK_AVAILABLE_FROM_NODE = "v24.0.0";

/**
 * Upper bound on bytes we will mlock in a single call. Production
 * wrap keys are 32 bytes (AES-256) or 64 bytes (ML-DSA-65 expanded
 * key material). Anything above 1 MiB is almost certainly a bug —
 * either the caller passed a heap snapshot, an entire request body,
 * or an unbounded buffer — and mlocking that much physical RAM would
 * block the process. Refuse early with a warn log so a misbehaving
 * caller can be diagnosed from the [PQC] log alone, without
 * freezing the host.
 */
export const MAX_MLOCK_BYTES = 1024 * 1024;

let warnedUnavailable = false;
let warnedOversize = false;
let mlockAvailableCache: boolean | null = null;

interface MlockCapableProcess {
  mlock?: (buf: Buffer) => void;
  munlock?: (buf: Buffer) => void;
}

/** Which backend won the feature-detect race. */
type MlockBackend = "process" | "native" | null;

/** Backend chosen for the current process. Computed once on the
 *  first call to {@link mlockKey} / {@link munlockKey}. */
let backendCache: MlockBackend = null;

function detectBackend(): MlockBackend {
  if (backendCache !== null) return backendCache;
  const proc = process as unknown as MlockCapableProcess;
  if (typeof proc.mlock === "function" && typeof proc.munlock === "function") {
    backendCache = "process";
    return backendCache;
  }
  if (nativeAddon.isAvailable()) {
    backendCache = "native";
    return backendCache;
  }
  backendCache = null;
  return backendCache;
}

/** Runtime feature-detect: is mlock available through any path?
 *  Cached after the first call. */
function checkMlockAvailable(): boolean {
  if (mlockAvailableCache !== null) return mlockAvailableCache;
  const backend = detectBackend();
  mlockAvailableCache = backend !== null;
  if (!mlockAvailableCache && !warnedUnavailable) {
    warnedUnavailable = true;
    pqcLog.warn(PQC_EVENT.MlockUnavailable, {
      status: "skipped",
      provider: `node:${process.version}`,
      detail:
        `process.mlock not available and N-API addon not built; ` +
        `wrap key not mlocked in RAM. ` +
        `Upgrade to Node ${MLOCK_AVAILABLE_FROM_NODE}+ with stable ` +
        `process.mlock, or run \`pnpm run build:native\` to enable ` +
        `the M6.B v2 N-API fallback (PQC whitepaper §6.3 v2).`,
    } satisfies PqcLogPayload);
  }
  return mlockAvailableCache;
}

/**
 * Lock a Buffer in physical RAM so it cannot be swapped to disk
 * and is excluded from core dumps (subject to kernel configuration).
 *
 * Defensive behavior:
 * - No-op on Node < 24.0.0 without the native addon built (one
 *   [PQC] mlock-unavailable warn per process).
 * - No-op on null / undefined / non-Buffer / empty input.
 * - Refuse to mlock buffers above {@link MAX_MLOCK_BYTES} (one warn
 *   per process) — protects against accidentally pinning a giant
 *   heap snapshot, which would freeze the host.
 * - On syscall failure, warn and continue. The wrap/unwrap path
 *   never throws from mlock; the operator sees the [PQC] log and
 *   can fix the underlying RLIMIT_MEMLOCK / CAP_IPC_LOCK issue.
 *
 * Callers should pass the wrap key buffer BEFORE returning it from
 * `OsKeyring.getActiveKey()` / `FileKeyring.readKey()` so the lock
 * covers the entire lifetime of the cached buffer.
 */
export function mlockKey(buf: Buffer | null | undefined, label: string): void {
  if (!buf || !Buffer.isBuffer(buf) || buf.length === 0) return;
  if (buf.length > MAX_MLOCK_BYTES) {
    if (!warnedOversize) {
      warnedOversize = true;
      pqcLog.warn(PQC_EVENT.Mlock, {
        status: "refused",
        provider: label,
        byteLength: buf.length,
        detail:
          `refusing to mlock ${buf.length} bytes (>MAX_MLOCK_BYTES=${MAX_MLOCK_BYTES}); ` +
          `this is almost certainly a caller bug — wrap keys are 32–64 bytes. ` +
          `Mlock once per process; check for missing size validation upstream.`,
      } satisfies PqcLogPayload);
    }
    return;
  }
  if (!checkMlockAvailable()) return;
  const backend = detectBackend();
  if (backend === null) {
    mlockAvailableCache = false;
    return;
  }
  try {
    if (backend === "process") {
      const proc = process as unknown as MlockCapableProcess;
      if (typeof proc.mlock !== "function") {
        mlockAvailableCache = false;
        return;
      }
      proc.mlock(buf);
    } else {
      // backend === "native": N-API addon calling mlock(2) directly.
      // Linux only. The addon throws on failure (e.g. EPERM,
      // ENOMEM) — caught below and logged.
      nativeAddon.mlockSync(buf);
    }
    // Production run-once log: emit at debug so the [PQC] log is
    // not flooded. Operators who want to verify mlock is active can
    // run the fork with PQC log level set to debug.
    pqcLog.debug(PQC_EVENT.Mlock, {
      status: "ok",
      provider: `${label} (backend=${backend})`,
      byteLength: buf.length,
      detail: `${process.platform}/${process.arch} node=${process.version}`,
    } satisfies PqcLogPayload);
  } catch (error) {
    pqcLog.warn(PQC_EVENT.Mlock, {
      status: "fail",
      provider: label,
      byteLength: buf.length,
      detail:
        `mlock(2) syscall failed on ${process.platform}/${process.arch} ` +
        `(backend=${backend}): ${(error as Error).message}. ` +
        `Operator action: set RLIMIT_MEMLOCK >= ${buf.length} ` +
        `(e.g. 'ulimit -l unlimited' as root, or grant CAP_IPC_LOCK).`,
    } satisfies PqcLogPayload);
  }
}

/**
 * Unlock a previously mlocked Buffer. Idempotent. No-op on Node
 * < 24.0.0 without the native addon built. Failures are swallowed:
 * the kernel releases pages on process exit anyway, and a failed
 * munlock does not indicate a security incident.
 */
export function munlockKey(buf: Buffer | null | undefined, label: string): void {
  if (!buf || !Buffer.isBuffer(buf) || buf.length === 0) return;
  if (!checkMlockAvailable()) return;
  const backend = detectBackend();
  if (backend === null) {
    mlockAvailableCache = false;
    return;
  }
  try {
    if (backend === "process") {
      const proc = process as unknown as MlockCapableProcess;
      if (typeof proc.munlock !== "function") {
        mlockAvailableCache = false;
        return;
      }
      proc.munlock(buf);
    } else {
      nativeAddon.munlockSync(buf);
    }
    pqcLog.debug(PQC_EVENT.Munlock, {
      status: "ok",
      provider: `${label} (backend=${backend})`,
    } satisfies PqcLogPayload);
  } catch {
    // Munlock failures are non-fatal. The page is freed when the
    // process exits or the buffer is GC'd; the OS does not
    // accidentally re-mlock a page.
  }
}

/** True iff mlock is available through any path. Tests use this to
 *  assert defensive behavior on Node 22 (no-op path) and real
 *  behavior on Node 24+ (process path) or when the native addon
 *  is built (native path). */
export function isMlockActive(): boolean {
  return checkMlockAvailable();
}

/** Which backend won the feature-detect race. Exported for tests
 *  and the [PQC] status log; not for production use. */
export function mlockBackend(): MlockBackend {
  return detectBackend();
}

/** Test hook: clear the cached feature-detect result and any
 *  "warned once" flags. Production code should not need this; the
 *  cache is set once and read. */
export function __resetMlockCacheForTests(): void {
  mlockAvailableCache = null;
  backendCache = null;
  warnedUnavailable = false;
  warnedOversize = false;
}
