// mlock-addon.js — lazy loader for the native mlock(2) N-API addon.
//
// Why lazy: production builds on Node 22 must work without the addon
// being built (e.g. developer machines, CI runners that only run
// vitest, or any host that does not have g++ / Python 3 in PATH).
// The addon is *only* used as a fallback when `process.mlock` is
// missing (i.e. on Node < 24.0.0 stable, or on Node 24.x builds where
// the mlock API was removed — verified for 24.15.0 on 2026-09-04).
//
// The addon is built via `pnpm run build:native` (or
// `npx node-gyp configure build` from src/security/native/) and the
// resulting `build/Release/mlock_addon.node` is loaded by `require()`
// on first call to `mlockSync` / `munlockSync`.
//
// If the build is missing or fails to load (e.g. native binary does
// not match the host's Node ABI), `isAvailable()` returns `false`,
// `loadError()` exposes the underlying error, and the synchronous
// helpers throw with the same `loadError()` message. The caller in
// mlock-helper.ts treats that as a transient no-op and logs once
// per process.
//
// Reference: PQC whitepaper §6.3 v2 (M6.B v2 mlock N-API fallback).

"use strict";

let addon = null;
let loadError = null;

try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  addon = require("./build/Release/mlock_addon.node");
} catch (err) {
  loadError = err;
}

function notBuiltError() {
  const detail = loadError && loadError.message ? loadError.message : "unknown";
  return new Error(
    "mlock_addon not built (run `pnpm run build:native` from repo " + "root): " + detail,
  );
}

module.exports = {
  /**
   * True if the native mlock(2) addon is loaded and ready to use.
   * Equivalent to a feature-detect: if false, the synchronous
   * helpers throw, and the caller should fall back to a no-op.
   */
  isAvailable() {
    return addon !== null;
  },

  /**
   * Underlying load error message, or null if the addon is loaded.
   * Useful for diagnostic logging in the [PQC] channel.
   */
  loadError() {
    return loadError && loadError.message ? loadError.message : null;
  },

  /**
   * Pin a Buffer in physical RAM via mlock(2). Throws on
   * failure (RLIMIT_MEMLOCK exceeded, EPERM, etc.) — the caller
   * in mlock-helper.ts catches and logs a single [PQC] warn per
   * process.
   *
   * @param {Buffer} buf — buffer to pin
   * @returns {number} — number of bytes mlocked
   */
  mlockSync(buf) {
    if (!addon) throw notBuiltError();
    return addon.mlock(buf);
  },

  /**
   * Reverse a previous mlock(2). Idempotent in the kernel sense:
   * the page is allowed to be swapped and core-dumped again. Safe
   * to call on a buffer that was not mlocked (kernel returns 0).
   *
   * @param {Buffer} buf — buffer to unpin
   * @returns {number} — number of bytes munlocked
   */
  munlockSync(buf) {
    if (!addon) throw notBuiltError();
    return addon.munlock(buf);
  },
};
