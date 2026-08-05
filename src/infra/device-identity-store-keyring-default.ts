// PQC step 2.3.5: lazily initialize the default wrapping provider for
// device-identity-store consumers. Backed by FileKeyringProvider
// (32-byte CSPRNG keys in ~/.openclaw/state/wrap-keys/, 0o700/0o600).
// Tests should call resetDefaultWrappingProviderForTest() to clear the cache.
import { createDefaultKeyringProvider } from "../security/keyring-provider.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";

let cachedProvider: WrappingKeyProvider | null = null;

export function getOrCreateDefaultWrappingProvider(): WrappingKeyProvider {
  if (!cachedProvider) {
    cachedProvider = createDefaultKeyringProvider();
  }
  return cachedProvider;
}

export function resetDefaultWrappingProviderForTest(): void {
  cachedProvider = null;
}
