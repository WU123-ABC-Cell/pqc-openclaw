// Type declarations for src/security/native/mlock-addon.cjs.
//
// The .cjs wrapper is a hand-written CommonJS module that lazy-loads
// the native addon (./build/Release/mlock_addon.node). This .d.ts
// exists purely so the TypeScript compiler (tsgo) can type-check
// the call sites in mlock-helper.ts without flagging TS7016
// (implicit any) on the bare CJS require().

declare module "./mlock-addon.cjs" {
  /**
   * True if the native mlock(2) addon is loaded and ready to use.
   */
  export function isAvailable(): boolean;

  /**
   * Underlying load error message, or null if the addon is loaded.
   * Useful for diagnostic logging in the [PQC] channel.
   */
  export function loadError(): string | null;

  /**
   * Pin a Buffer in physical RAM via mlock(2). Throws on
   * failure (RLIMIT_MEMLOCK exceeded, EPERM, etc.) — the caller
   * in mlock-helper.ts catches and logs a single [PQC] warn per
   * process.
   *
   * @param buf — buffer to pin
   * @returns number of bytes mlocked
   */
  export function mlockSync(buf: Buffer): number;

  /**
   * Reverse a previous mlock(2). Idempotent in the kernel sense:
   * the page is allowed to be swapped and core-dumped again. Safe
   * to call on a buffer that was not mlocked (kernel returns 0).
   *
   * @param buf — buffer to unpin
   * @returns number of bytes munlocked
   */
  export function munlockSync(buf: Buffer): number;
}
