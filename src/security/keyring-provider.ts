// Wrapping-key providers for the device-identity wrap-key feature
// (PQC whitepaper 2.2.5 + 2.2.5.A + 2.2.5.B).
//
// This module owns the read-side of the wrap-key: where does the
// 32-byte AES-256 key live? M5's secret-wrapping.ts is the envelope;
// this file decides which secret goes into it. The contract is the
// `WrappingKeyProvider` interface (re-declared here as `KeyringProvider`
// for the file / env / OS flavours; the same shape also lives inline
// in secret-wrapping.ts so that module can stay self-contained).
//
// Implementations:
//   * file-keyring: read a base64url-encoded 32-byte key from a file
//     at a known path. File permissions are checked (0600 on POSIX);
//     loose permissions are a config error.
//   * env-keyring: read a base64url-encoded 32-byte key from an env var.
//     Intended for CI / container deployments; not as a long-term store.
//   * os-keyring: a stub here; the real implementation lives in
//     `os-keyring.ts` and uses @napi-rs/keyring when available. The
//     split keeps this file dependency-free so tests run on any
//     platform without native modules.
//
// Compose the providers with `CompositeKeyring` (M6's "auto-inject
// default keyring", whitepaper 2.2.5.A): try the active source, fall
// back to the others in order.
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { OsKeyring } from "./os-keyring.js";
import { mlockKey, munlockKey, isMlockActive } from "./mlock-helper.js";

/** Stable id of a keyring entry. The wrap envelope records this id so
 *  a rotation can re-encrypt the payload with the new active key
 *  without losing the public side. */
export type KeyId = string;

/** 32-byte AES-256 key plus the id it was looked up under. */
export interface ActiveWrappingKey {
  key: Buffer;
  keyId: KeyId;
}

/** Contract that all keyring providers satisfy. The same shape is
 *  duplicated in `secret-wrapping.ts` to keep that module dependency-
 *  free. If you add a method here, mirror it in the inline interface
 *  in `secret-wrapping.ts`. */
export interface KeyringProvider {
  getActiveKey(): ActiveWrappingKey;
  getKeyById(keyId: KeyId): Buffer | null;
}

/** Decode a 32-byte AES-256 key from a base64url (or base64) string.
 *  Throws on wrong length or malformed encoding. The two encodings are
 *  accepted so operators can paste a key from either format; the
 *  wire format on disk / in env is always base64url by convention. */
export function decodeBase64UrlKey(encoded: string, label: string): Buffer {
  if (typeof encoded !== "string" || encoded.length === 0) {
    throw new Error(`keyring: ${label} must be a non-empty string`);
  }
  // Buffer.from with "base64url" is permissive; it accepts both padded
  // and unpadded forms. We then check the byte length.
  const key = Buffer.from(encoded, "base64url");
  if (key.length !== 32) {
    throw new Error(
      `keyring: ${label} must decode to exactly 32 bytes (AES-256), got ${key.length}`,
    );
  }
  return key;
}

/** Encode a 32-byte buffer as base64url (no padding). The wire format
 *  for file-keyring and env-keyring. */
export function encodeBase64UrlKey(key: Buffer): string {
  if (key.length !== 32) {
    throw new Error(`keyring: key must be 32 bytes (AES-256), got ${key.length}`);
  }
  return Buffer.from(key).toString("base64url");
}

/** Generate a fresh 32-byte key. Used by `openclaw wrap-key` (M8) and
 *  by tests. Not used by the read path. */
export function generateWrappingKey(): Buffer {
  return randomBytes(32);
}

/** File-backed keyring. Reads a base64url-encoded 32-byte key from
 *  `keyPath`. POSIX file permissions are checked (must be 0600 or 0400
 *  after following the owner's umask); broader permissions are a
 *  config error because the key is a plaintext secret. */
export class FileKeyring implements KeyringProvider {
  private cachedKey: Buffer | null = null;

  constructor(
    private readonly keyPath: string,
    private readonly keyId: KeyId = "file-keyring",
  ) {
    if (typeof keyPath !== "string" || keyPath.length === 0) {
      throw new Error("FileKeyring: keyPath must be a non-empty string");
    }
    if (!isAbsolute(keyPath)) {
      // Refuse relative paths so a CWD change cannot silently move the
      // key file out from under us.
      throw new Error(`FileKeyring: keyPath must be absolute, got ${keyPath}`);
    }
  }

  /** Resolve the on-disk path (used for diagnostics and tests). */
  getKeyPath(): string {
    return this.keyPath;
  }

  getActiveKey(): ActiveWrappingKey {
    return { key: this.readKey(), keyId: this.keyId };
  }

  getKeyById(keyId: KeyId): Buffer | null {
    if (keyId !== this.keyId) {
      return null;
    }
    return this.readKey();
  }

  private readKey(): Buffer {
    if (this.cachedKey) {
      // The cache exists so repeated wrap / unwrap calls in one
      // process lifetime don't re-read the file. Operators who want
      // rotation call `invalidate()` after swapping the file.
      return this.cachedKey;
    }
    if (!existsSync(this.keyPath)) {
      throw new Error(`FileKeyring: key file not found: ${this.keyPath}`);
    }
    const stat = statSync(this.keyPath);
    if (process.platform !== "win32") {
      // POSIX: refuse world- or group-readable keys. 0600 (owner rw)
      // and 0400 (owner r) are the only acceptable modes; everything
      // else risks exposing the key to other users on the host.
      const mode = stat.mode & 0o777;
      if ((mode & 0o077) !== 0) {
        throw new Error(
          `FileKeyring: key file ${this.keyPath} has unsafe permissions ` +
            `(mode=${mode.toString(8).padStart(4, "0")}); expected 0600 or 0400`,
        );
      }
    }
    const raw = readFileSync(this.keyPath, "utf8").trim();
    const key = decodeBase64UrlKey(raw, `file:${this.keyPath}`);
    this.cachedKey = key;
    // mlock: lock the wrap key in physical RAM. No-op on Node < 24.0.0.
    // PQC whitepaper §6.3 v2 (2026-09-01 follow-up).
    mlockKey(this.cachedKey, `file:${this.keyPath}`);
    return key;
  }

  /** Drop the in-memory cache. Used by M7 rotation after the file
   *  has been swapped on disk. */
  invalidate(): void {
    if (this.cachedKey) {
      munlockKey(this.cachedKey, `file:${this.keyPath}`);
    }
    this.cachedKey = null;
  }

  /** M6.B v2: release any mlocked buffer this keyring is holding.
   *  Called on process shutdown by the module-level hook to munlock
   *  before the OS reclaims the pages. Idempotent. */
  release(): void {
    if (this.cachedKey) {
      munlockKey(this.cachedKey, `file:${this.keyPath}`);
    }
  }
}

/** Environment-variable-backed keyring. Reads a base64url-encoded
 *  32-byte key from `process.env[name]`. Intended for CI / container
 *  deployments; the variable is read on every `getActiveKey` call so
 *  a parent process can rotate the key by re-exporting the env var
 *  and re-instantiating the keyring (no in-memory cache). */
export class EnvKeyring implements KeyringProvider {
  constructor(
    private readonly envName: string,
    private readonly env: NodeJS.ProcessEnv = process.env,
    private readonly keyId: KeyId = "env-keyring",
  ) {
    if (typeof envName !== "string" || envName.length === 0) {
      throw new Error("EnvKeyring: envName must be a non-empty string");
    }
  }

  getActiveKey(): ActiveWrappingKey {
    return { key: this.readKey(), keyId: this.keyId };
  }

  getKeyById(keyId: KeyId): Buffer | null {
    if (keyId !== this.keyId) {
      return null;
    }
    return this.readKey();
  }

  private readKey(): Buffer {
    const raw = this.env[this.envName];
    if (typeof raw !== "string" || raw.length === 0) {
      throw new Error(
        `EnvKeyring: env var ${this.envName} is not set or empty; ` +
          `set it to a base64url-encoded 32-byte AES-256 key`,
      );
    }
    return decodeBase64UrlKey(raw, `env:${this.envName}`);
  }
}

/** Composite keyring that tries providers in order. Used for
 *  "auto-inject default keyring" (whitepaper 2.2.5.A): a primary
 *  keyring (e.g. OS keyring on macOS) and one or more fallbacks
 *  (e.g. file keyring for tests / CI). `getKeyById` walks every
 *  provider so historical keys can still be unwrapped during a
 *  rotation grace period. */
export class CompositeKeyring implements KeyringProvider {
  private readonly providers: KeyringProvider[];

  constructor(providers: KeyringProvider[]) {
    if (!Array.isArray(providers) || providers.length === 0) {
      throw new Error("CompositeKeyring: providers must be a non-empty array");
    }
    this.providers = providers.slice();
  }

  getActiveKey(): ActiveWrappingKey {
    const errors: string[] = [];
    for (const provider of this.providers) {
      try {
        return provider.getActiveKey();
      } catch (error) {
        errors.push(`${provider.constructor.name}: ${(error as Error).message}`);
      }
    }
    throw new Error(
      `CompositeKeyring: no provider returned an active key. Errors: ${errors.join("; ")}`,
    );
  }

  getKeyById(keyId: KeyId): Buffer | null {
    for (const provider of this.providers) {
      try {
        const key = provider.getKeyById(keyId);
        if (key) {
          return key;
        }
      } catch {
        // A failing provider is not an error for `getKeyById`; the
        // composite walks all providers and returns the first match.
      }
    }
    return null;
  }

  /** The number of providers in the composite. Useful for tests
   *  asserting that "auto-inject" added a primary + a fallback. */
  get size(): number {
    return this.providers.length;
  }

  /** M6.B v2: release mlocked buffers in any inner provider that
   *  supports it. Used by the module-level shutdown hook. */
  release(): void {
    for (const provider of this.providers) {
      if (typeof (provider as { release?: () => void }).release === "function") {
        try {
          (provider as { release: () => void }).release();
        } catch {
          // best-effort
        }
      }
    }
  }
}

/** Resolve a keyring by reading the optional configuration block. This
 *  is the M6+ factory the CLI / Doctor will use to auto-inject the
 *  default keyring. Each entry's `kind` selects an implementation;
 *  the file and env variants need no extra setup. The OS variant
 *  needs `@napi-rs/keyring` and lives in `os-keyring.ts`. */
export type KeyringConfig =
  | { kind: "file"; keyPath: string; keyId?: KeyId }
  | { kind: "env"; envName: string; keyId?: KeyId }
  | { kind: "os"; service: string; account: string; keyId?: KeyId }
  | { kind: "composite"; providers: KeyringConfig[] };

/** Map a `KeyringConfig` to a `KeyringProvider`. The OS variant is
 *  imported statically from `./os-keyring.ts`; the M6.B swap to
 *  @napi-rs/keyring lives in that file. */
export function createKeyring(config: KeyringConfig): KeyringProvider {
  switch (config.kind) {
    case "file":
      return new FileKeyring(config.keyPath, config.keyId ?? "file-keyring");
    case "env":
      return new EnvKeyring(config.envName, process.env, config.keyId ?? "env-keyring");
    case "os":
      return new OsKeyring(config.service, config.account, config.keyId ?? "os-keyring");
    case "composite":
      return new CompositeKeyring(config.providers.map(createKeyring));
    default: {
      const exhaustive: never = config;
      throw new Error(`createKeyring: unknown config kind: ${JSON.stringify(exhaustive)}`);
    }
  }
}

/** Convenience for tests + a future "default config" path: return the
 *  set of stable key ids the keyring is willing to resolve. The
 *  `composite` variant returns the union of its providers' ids when
 *  each provider exposes a known static id (File and Env do, OS does
 *  not — its id is the service+account name and is opaque to us). */
export function knownKeyIds(provider: KeyringProvider): KeyId[] {
  if (provider instanceof FileKeyring) {
    return [provider.getKeyPath()];
  }
  if (provider instanceof EnvKeyring) {
    return [provider["envName" as keyof EnvKeyring] as unknown as KeyId];
  }
  if (provider instanceof CompositeKeyring) {
    // The composite itself doesn't carry ids; recurse on its providers.
    const out: KeyId[] = [];
    for (const inner of (provider as unknown as { providers: KeyringProvider[] }).providers) {
      out.push(...knownKeyIds(inner));
    }
    return out;
  }
  return [];
}

/** Re-export a couple of types the runtime (M5) already declared
 *  locally so consumers have a single import surface. */
export type { ActiveWrappingKey as KeyringActiveKey };

// Re-export the OS keyring stub so the test file (and the future
// M6.B real implementation) can import the class from one place.
// The actual factory uses a dynamic `require` to avoid an ESM
// circular import at static-parse time; the static re-export is
// fine because os-keyring.ts does not import back into this file.
export { OsKeyring } from "./os-keyring.js";

/** Module-level cache for `getDefaultKeyringFromEnv`. Without this
 *  cache, every call to `getDefaultKeyringFromEnv` would build a
 *  fresh `FileKeyring` whose internal `cachedKey` is empty, so
 *  `getActiveKey()` would re-read the key file on every invocation.
 *  The `cachedKey` field on the class is per-instance, so the
 *  instance itself has to be reused for caching to be effective. */
let cachedDefaultKeyring: KeyringProvider | null | undefined = undefined;

/** Build a process-level cached keyring from environment variables.
 *  Implements the M5.5 "auto-inject default keyring" path
 *  (whitepaper 2.2.5.A) and the M6.B OS-keyring deployment
 *  (whitepaper 2.2.5.B).
 *
 *  Reads:
 *  - `OPENCLAW_WRAP_KEY_OS_SERVICE` (optional): OS keyring service
 *    name (e.g. "openclaw"). Required together with
 *    `OPENCLAW_WRAP_KEY_OS_ACCOUNT` to enable the OS-keyring
 *    provider. M6.B.
 *  - `OPENCLAW_WRAP_KEY_OS_ACCOUNT` (optional): OS keyring account
 *    (per-key entry name, typically the keyId). M6.B.
 *  - `OPENCLAW_WRAP_KEY_OS_ID` (optional): logical key id for the
 *    OS-keyring entry, defaults to `"os-keyring"`. Mapped to
 *    `mldsa_private_key_wrap_key_id`.
 *  - `OPENCLAW_WRAP_KEY_FILE` (optional): absolute path to the
 *    base64url-encoded 32-byte AES-256 wrapping key. The `FileKeyring`
 *    constructor enforces absolute-path + 0600/0400 mode at construction.
 *  - `OPENCLAW_WRAP_KEY_ID` (optional): logical key id for the
 *    file-keyring entry, defaults to `"file-keyring"`.
 *
 *  Composition:
 *  - OS only → `OsKeyring`.
 *  - File only → `FileKeyring` (backward compat with M5.5).
 *  - Both → `CompositeKeyring([OsKeyring, FileKeyring])` so the
 *    OS keyring is the active source and the file is the fallback
 *    during the M6.B migration window. This is the recommended
 *    post-migration shape: the OS keyring is the live source of
 *    truth, the file is the recovery backup until the operator
 *    deletes it.
 *
 *  Returns `null` when neither source is configured, so callers can
 *  "auto-inject if configured" without forcing a keyring on
 *  environments that don't need one (tests, the unwrapped mode that
 *  predates M5, etc.).
 *
 *  The first call constructs and caches; subsequent calls return
 *  the same instance, so per-class caches (FileKeyring.cachedKey,
 *  OsKeyring's loaded Entry) are preserved and `getActiveKey()` is
 *  a memory lookup after the first read.
 */
export function getDefaultKeyringFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): KeyringProvider | null {
  if (cachedDefaultKeyring !== undefined) {
    return cachedDefaultKeyring;
  }
  const keyPath = env.OPENCLAW_WRAP_KEY_FILE;
  const osService = env.OPENCLAW_WRAP_KEY_OS_SERVICE;
  const osAccount = env.OPENCLAW_WRAP_KEY_OS_ACCOUNT;
  const hasFile = typeof keyPath === "string" && keyPath.length > 0;
  const hasOs =
    typeof osService === "string" &&
    osService.length > 0 &&
    typeof osAccount === "string" &&
    osAccount.length > 0;

  if (!hasFile && !hasOs) {
    cachedDefaultKeyring = null;
    return null;
  }

  const providers: KeyringProvider[] = [];
  if (hasOs) {
    const osKeyId =
      (env.OPENCLAW_WRAP_KEY_OS_ID as KeyId | undefined) ?? "os-keyring";
    providers.push(new OsKeyring(osService, osAccount, osKeyId));
  }
  if (hasFile) {
    const fileKeyId =
      (env.OPENCLAW_WRAP_KEY_ID as KeyId | undefined) ?? "file-keyring";
    providers.push(new FileKeyring(keyPath, fileKeyId));
  }

  cachedDefaultKeyring =
    providers.length === 1 ? providers[0] : new CompositeKeyring(providers);
  return cachedDefaultKeyring;
}

/** Drop the module-level default keyring cache. Tests use this to
 *  verify that env-var changes between calls are picked up; production
 *  code should not need it. */
export function resetDefaultKeyringCache(): void {
  cachedDefaultKeyring = undefined;
}

/** M6.B v2: release all mlocked buffers in the default keyring cache.
 *  Called on process shutdown by the hook installed below. Idempotent
 *  and safe to call multiple times. */
export function releaseDefaultKeyring(): void {
  const keyring = cachedDefaultKeyring;
  if (!keyring) return;
  if (typeof (keyring as { release?: () => void }).release === "function") {
    (keyring as { release: () => void }).release();
  }
}

/** M6.B v2: install a one-shot process-exit hook that releases mlocked
 *  wrap-key buffers before the OS reclaims the pages. Best-effort:
 *  `process.on("exit", ...)` is fire-and-forget and runs after Node
 *  has shut down most subsystems, so we keep the work to a single
 *  `releaseDefaultKeyring()` call. */
if (typeof process !== "undefined" && typeof process.on === "function") {
  process.on("exit", () => {
    try {
      releaseDefaultKeyring();
    } catch {
      // best-effort: ignore any error during shutdown
    }
  });
}
