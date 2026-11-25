import { createRequire } from "node:module";
import path from "node:path";
import { resolveOpenClawPackageRootSync } from "../../infra/openclaw-root.js";

type NativeMlockBinding = {
  mlock(buf: Buffer): number;
  munlock(buf: Buffer): number;
  secureCopy(buf: Buffer): Buffer;
  secureMemzero(buf: Buffer): number;
};

// Anchor the lookup to this package. Bundling moves this module to dist,
// while node-gyp always produces the optional binary in the source tree.
const require = createRequire(import.meta.url);
const packageRoot = resolveOpenClawPackageRootSync({ moduleUrl: import.meta.url });
let addon: NativeMlockBinding | null = null;
let loadError: Error | null = null;
try {
  if (!packageRoot) {
    throw new Error("OpenClaw package root not found");
  }
  addon = require(
    path.join(packageRoot, "src", "security", "native", "build", "Release", "mlock_addon.node"),
  ) as NativeMlockBinding;
} catch (error) {
  loadError = error instanceof Error ? error : new Error(String(error));
}

function notBuiltError() {
  const detail = loadError?.message ?? "unknown";
  return new Error(
    `mlock_addon not built (run \`pnpm run build:native\` from repo root): ${detail}`,
  );
}

export default {
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
    return loadError?.message ?? null;
  },

  /**
   * Pin a Buffer in physical RAM via mlock(2). This prevents swapping but does
   * not exclude shared Node slab pages from core dumps. Throws on failure
   * (RLIMIT_MEMLOCK exceeded, EPERM, etc.) — the caller
   * in mlock-helper.ts catches and logs a single [PQC] warn per
   * process.
   *
   * @param {Buffer} buf — buffer to pin
   * @returns {number} — number of bytes mlocked
   */
  mlockSync(buf: Buffer) {
    if (!addon) {
      throw notBuiltError();
    }
    return addon.mlock(buf);
  },

  /**
   * Reverse a previous mlock(2). Safe
   * to call on a buffer that was not mlocked (kernel returns 0).
   *
   * @param {Buffer} buf — buffer to unpin
   * @returns {number} — number of bytes munlocked
   */
  munlockSync(buf: Buffer) {
    if (!addon) {
      throw notBuiltError();
    }
    return addon.munlock(buf);
  },

  /** Copy a Buffer into addon-owned locked memory. On Linux the mapping is
   * also excluded from core dumps with MADV_DONTDUMP. The mapping is zeroed,
   * unlocked, and released by its native finalizer.
   * @param {Buffer} buf
   * @returns {Buffer}
   */
  secureCopySync(buf: Buffer) {
    if (!addon) {
      throw notBuiltError();
    }
    return addon.secureCopy(buf);
  },

  /** Overwrite a Buffer through a native volatile zeroing loop.
   * @param {Buffer} buf
   * @returns {number}
   */
  secureZeroSync(buf: Buffer) {
    if (!addon) {
      throw notBuiltError();
    }
    return addon.secureMemzero(buf);
  },
};
