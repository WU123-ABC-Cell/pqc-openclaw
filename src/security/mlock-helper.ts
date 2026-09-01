// mlock-helper.ts — defensive mlock for in-memory secret material
// (PQC whitepaper §6.3 v2, M6.B OsKeyring 真部署 100% follow-up, 9/1/2026).
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
// Node support: process.mlock / process.munlock were added in Node
// 24.0.0 (stable). Before that, `typeof process.mlock === undefined`.
// We verified 2026-09-01 on Node 22.23.1:
//
//   $ node -e "console.log(typeof process.mlock)"
//   undefined
//   $ node --experimental-mlock -e "console.log(typeof process.mlock)"
//   node: bad option: --experimental-mlock
//   $ NODE_OPTIONS='--experimental-mlock' node -e "console.log(typeof process.mlock)"
//   node: --experimental-mlock is not allowed in NODE_OPTIONS
//
// The fork's `package.json` `engines.node` accepts `>=24.15.0 <25`,
// so a Node 24 LTS upgrade is the path to using this on a production
// build. Until then, the helpers no-op + log a single warning so
// the operator can see in the [PQC] log that mlock is skipped.
//
// This is defense-in-depth, not a hard guarantee: even with mlock
// active, an attacker with root on the host can read process memory.
// The point is to raise the bar against passive attacks (cold-boot,
// disk image after theft, kernel-privileged attacker without ptrace).
import { pqcLog, PQC_EVENT, type PqcLogPayload } from "../logging/pqc-log.js";

/** Node version where process.mlock became stable (24.0.0). */
const MLOCK_AVAILABLE_FROM_NODE = "v24.0.0";

let warnedUnavailable = false;
let mlockAvailableCache: boolean | null = null;

interface MlockCapableProcess {
  mlock?: (buf: Buffer) => void;
  munlock?: (buf: Buffer) => void;
}

/** Runtime feature-detect: does process.mlock exist as a callable
 *  function on this Node version? Cached after the first call. */
function checkMlockAvailable(): boolean {
  if (mlockAvailableCache !== null) return mlockAvailableCache;
  const proc = process as unknown as MlockCapableProcess;
  mlockAvailableCache = typeof proc.mlock === "function" && typeof proc.munlock === "function";
  if (!mlockAvailableCache && !warnedUnavailable) {
    warnedUnavailable = true;
    pqcLog.warn(PQC_EVENT.MlockUnavailable, {
      status: "skipped",
      provider: `node:${process.version}`,
      detail: `process.mlock not available; wrap key not mlocked in RAM. Upgrade to Node ${MLOCK_AVAILABLE_FROM_NODE}+ for mlock (PQC whitepaper §6.3 v2 follow-up).`,
    } satisfies PqcLogPayload);
  }
  return mlockAvailableCache;
}

/** Lock a Buffer in physical RAM so it cannot be swapped to disk
 *  and is excluded from core dumps (subject to kernel configuration).
 *  No-op on Node < 24.0.0 with a single [PQC] mlock-unavailable
 *  warning. Callers should pass the wrap key buffer before returning
 *  it from getActiveKey() / getKeyById(). */
export function mlockKey(buf: Buffer | null | undefined, label: string): void {
  if (!buf || !Buffer.isBuffer(buf) || buf.length === 0) return;
  if (!checkMlockAvailable()) return;
  try {
    (process as unknown as MlockCapableProcess).mlock!(buf);
    pqcLog.info(PQC_EVENT.Mlock, {
      status: "ok",
      provider: label,
      byteLength: buf.length,
    } satisfies PqcLogPayload);
  } catch (error) {
    pqcLog.warn(PQC_EVENT.Mlock, {
      status: "fail",
      provider: label,
      detail: `mlock(2) syscall failed: ${(error as Error).message} (may need CAP_IPC_LOCK or 'ulimit -l unlimited')`,
    } satisfies PqcLogPayload);
  }
}

/** Unlock a previously mlocked Buffer. Idempotent. No-op on Node
 *  < 24.0.0. Failures are swallowed: the kernel releases pages on
 *  process exit anyway, and a failed munlock does not indicate a
 *  security incident. */
export function munlockKey(buf: Buffer | null | undefined, label: string): void {
  if (!buf || !Buffer.isBuffer(buf) || buf.length === 0) return;
  if (!checkMlockAvailable()) return;
  try {
    (process as unknown as MlockCapableProcess).munlock!(buf);
    pqcLog.debug(PQC_EVENT.Munlock, {
      status: "ok",
      provider: label,
    } satisfies PqcLogPayload);
  } catch {
    // Munlock failures are non-fatal. The page is freed when the
    // process exits or the buffer is GC'd; the OS does not
    // accidentally re-mlock a page.
  }
}

/** True iff process.mlock is available on this Node version. Tests
 *  use this to assert defensive behavior on Node 22 (no-op path) and
 *  real behavior on Node 24+ (active path). */
export function isMlockActive(): boolean {
  return checkMlockAvailable();
}

/** Test hook: clear the cached feature-detect result. Production
 *  code should not need this; the cache is set once and read. */
export function __resetMlockCacheForTests(): void {
  mlockAvailableCache = null;
  warnedUnavailable = false;
}
