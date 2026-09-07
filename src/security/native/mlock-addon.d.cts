// Type declarations for the CommonJS native-addon loader.

declare const nativeAddon: {
  /** True when the compiled N-API addon loaded successfully. */
  isAvailable(): boolean;

  /** The loader error message, or null when the addon is available. */
  loadError(): string | null;

  /** Pin a Buffer with mlock(2), returning the locked byte count. */
  mlockSync(buf: Buffer): number;

  /** Release a Buffer with munlock(2), returning the unlocked byte count. */
  munlockSync(buf: Buffer): number;
};

export = nativeAddon;
