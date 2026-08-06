// PQC step 2.3.5: persistent keyring providers for AES-256-GCM wrapping keys.
//
// Three backends, all implementing WrappingKeyProvider:
// 1. EnvKeyringProvider   - reads OPENCLAW_WRAP_KEY (hex or base64url) + OPENCLAW_WRAP_KEY_ID
//                          Useful for tests, CI, ephemeral deployments.
// 2. FileKeyringProvider  - persists 32-byte random keys to a dedicated directory
//                          (default: ~/.openclaw/state/wrap-keys/).
//                          Protection: directory 0o700, key files 0o600.
// 3. CompositeKeyringProvider - tries primary first, falls back to secondary on error.
//
// All keys are 32 random bytes (256 bits) from CSPRNG. The key value is the
// secret; no additional encryption. Protection relies on filesystem perms
// or OS keyring ACLs (the latter is a follow-up PR using @napi-rs/keyring).

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  chmodSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { join } from "node:path";
import { homedir } from "node:os";
import type { ActiveWrappingKey, WrappingKeyProvider } from "./secret-wrapping.js";
import {
  exportWrapKey,
  importWrapKey,
  type ExportedWrapKey,
  type ExportOptions,
  type ImportOptions,
  WrapKeyBackupError,
} from "./wrap-key-backup.js";

/** Minimal shape of the @napi-rs/keyring `Entry` class. Optional dep. */
export interface NapiRsKeyringEntry {
  getPassword(): string | null;
  setPassword(password: string): void;
  deletePassword(): boolean;
}

export interface NapiRsKeyringModule {
  Entry: new (service: string, username: string) => NapiRsKeyringEntry;
}

function defaultKeyringLoader(): NapiRsKeyringModule | null {
  try {
    const require = createRequire(import.meta.url);
    return require("@napi-rs/keyring") as NapiRsKeyringModule;
  } catch {
    return null;
  }
}

const KEY_BYTES = 32;
const KEY_ID_BYTES = 16; // 128 bits of randomness
const KEY_ID_PREFIX = "openclaw-wrap-";
const KEYRING_DIR_MODE = 0o700;
const KEY_FILE_MODE = 0o600;
const ACTIVE_KEY_ID_FILE = "active-key-id";

const ENV_KEY = "OPENCLAW_WRAP_KEY";
const ENV_KEY_ID = "OPENCLAW_WRAP_KEY_ID";

function defaultKeyringDir(): string {
  return join(homedir(), ".openclaw", "state", "wrap-keys");
}

export function generateKeyId(): string {
  return `${KEY_ID_PREFIX}${randomBytes(KEY_ID_BYTES).toString("hex")}`;
}

function ensureDir(dir: string): void {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: KEYRING_DIR_MODE });
  }
  chmodSync(dir, KEYRING_DIR_MODE);
}

function parseKeyString(raw: string): Buffer {
  // Try hex first (most common), then base64url
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    const buf = Buffer.from(raw, "hex");
    if (buf.length === KEY_BYTES) return buf;
  }
  try {
    const buf = Buffer.from(raw, "base64url");
    if (buf.length === KEY_BYTES) return buf;
  } catch {
    // fall through
  }
  throw new Error(
    `wrapping key must be ${KEY_BYTES} bytes (hex or base64url), got ${raw.length} chars`,
  );
}

/**
 * Read wrapping key from environment variables.
 * OPENCLAW_WRAP_KEY: 32 bytes as hex or base64url
 * OPENCLAW_WRAP_KEY_ID: key id (defaults to "env" if unset)
 */
export class EnvKeyringProvider implements WrappingKeyProvider {
  constructor(
    private readonly env: NodeJS.ProcessEnv = process.env,
  ) {}

  getActiveKey(): ActiveWrappingKey {
    const raw = this.env[ENV_KEY];
    if (!raw) {
      throw new Error(`${ENV_KEY} is not set`);
    }
    const key = parseKeyString(raw);
    const keyId = this.env[ENV_KEY_ID] ?? "env";
    return { key, keyId };
  }

  getKeyById(keyId: string): Buffer | null {
    const active = this.getActiveKey();
    if (keyId !== active.keyId) {
      return null;
    }
    return active.key;
  }
}

/**
 * Persist 32-byte random keys to per-key files in a dedicated directory.
 * Layout:
 *   <dir>/
 *     active-key-id          (text file: the currently active key id)
 *     <key-id>.key           (binary file: 32 random bytes, mode 0o600)
 */
export class FileKeyringProvider implements WrappingKeyProvider {
  private readonly activeKeyIdPath: string;
  private readonly keyId: string;

  constructor(
    private readonly dir: string = defaultKeyringDir(),
    keyId?: string,
  ) {
    this.activeKeyIdPath = join(this.dir, ACTIVE_KEY_ID_FILE);
    ensureDir(this.dir);
    // If keyId is provided, use it (allows key rotation) and persist it
    // as the active key. Otherwise, load the persisted id or generate a new one.
    if (keyId !== undefined) {
      this.keyId = keyId;
      this.persistActiveKeyId(keyId);
    } else {
      this.keyId = this.loadOrGenerateKeyId();
    }
  }

  getActiveKey(): ActiveWrappingKey {
    const key = this.loadOrCreateKey(this.keyId);
    return { key, keyId: this.keyId };
  }

  getKeyById(keyId: string): Buffer | null {
    const path = this.keyPath(keyId);
    if (!existsSync(path)) {
      return null;
    }
    return readFileSync(path);
  }

  private loadOrGenerateKeyId(): string {
    if (existsSync(this.activeKeyIdPath)) {
      const persisted = readFileSync(this.activeKeyIdPath, "utf8").trim();
      if (persisted) {
        return persisted;
      }
    }
    const newId = generateKeyId();
    this.persistActiveKeyId(newId);
    return newId;
  }

  private persistActiveKeyId(keyId: string): void {
    writeFileSync(this.activeKeyIdPath, keyId, { mode: KEY_FILE_MODE });
  }

  private loadOrCreateKey(keyId: string): Buffer {
    const path = this.keyPath(keyId);
    if (existsSync(path)) {
      return readFileSync(path);
    }
    const key = randomBytes(KEY_BYTES);
    writeFileSync(path, key, { mode: KEY_FILE_MODE });
    return key;
  }


  // --- backup / restore (PQC 2.3.5.D) ---

  /** Export the currently active wrap key to a passphrase-encrypted backup blob. */
  exportActiveKey(options: ExportOptions): ExportedWrapKey {
    const { key, keyId } = this.getActiveKey();
    return exportWrapKey(key, keyId, options);
  }

  /** Export any known wrap key by id. Throws if the key is not in the keyring. */
  exportKey(keyId: string, options: ExportOptions): ExportedWrapKey {
    const key = this.getKeyById(keyId);
    if (!key) {
      throw new WrapKeyBackupError(`unknown wrap key id: ${keyId}`);
    }
    return exportWrapKey(key, keyId, options);
  }

  /**
   * Import a backup blob and persist the recovered key to disk.
   * If the imported keyId matches the current active key id, the key is replaced;
   * otherwise the key is added as an additional entry (rotation history).
   */
  importKey(blob: ExportedWrapKey, options: ImportOptions): { keyId: string; becameActive: boolean } {
    const { key, keyId } = importWrapKey(blob, options);
    const path = this.keyPath(keyId);
    writeFileSync(path, key, { mode: KEY_FILE_MODE });
    const becameActive = keyId === this.keyId;
    if (becameActive) {
      this.persistActiveKeyId(keyId);
    }
    return { keyId, becameActive };
  }

  private keyPath(keyId: string): string {
    return join(this.dir, `${keyId}.key`);
  }
}

/**
 * OS keyring provider backed by @napi-rs/keyring (Keychain / libsecret / Credential Vault).
 * Falls back to throwing when the native module is unavailable; pair with
 * CompositeKeyringProvider(FileKeyringProvider) for graceful degradation.
 *
 * The native module is loaded lazily via the `loader` parameter to keep tests
 * and unsupported platforms working. In production, defaultKeyringLoader() is used.
 */
export class OSKeyringProvider implements WrappingKeyProvider {
  private readonly module: NapiRsKeyringModule | null;

  constructor(
    private readonly service: string = "openclaw",
    private readonly keyId: string = generateKeyId(),
    private readonly loader: () => NapiRsKeyringModule | null = defaultKeyringLoader,
  ) {
    this.module = loader();
  }

  getActiveKey(): ActiveWrappingKey {
    if (!this.module) {
      throw new Error("@napi-rs/keyring not available");
    }
    const entry = new this.module.Entry(this.service, this.keyId);
    let password = entry.getPassword();
    if (!password) {
      const key = randomBytes(KEY_BYTES).toString("base64url");
      entry.setPassword(key);
      password = key;
    }
    return { key: Buffer.from(password, "base64url"), keyId: this.keyId };
  }

  getKeyById(keyId: string): Buffer | null {
    if (!this.module) return null;
    try {
      const entry = new this.module.Entry(this.service, keyId);
      const password = entry.getPassword();
      return password ? Buffer.from(password, "base64url") : null;
    } catch {
      return null;
    }
  }

  isAvailable(): boolean {
    return this.module !== null;
  }
}

/**
 * Composite: try primary first, fall back to secondary on errors.
 * - getActiveKey: primary succeeds -> use it; primary throws -> fall back
 * - getKeyById: query primary first, then secondary (so rotated keys
 *   that were migrated still work)
 */
export class CompositeKeyringProvider implements WrappingKeyProvider {
  constructor(
    private readonly primary: WrappingKeyProvider,
    private readonly fallback: WrappingKeyProvider,
  ) {}

  getActiveKey(): ActiveWrappingKey {
    try {
      return this.primary.getActiveKey();
    } catch {
      return this.fallback.getActiveKey();
    }
  }

  getKeyById(keyId: string): Buffer | null {
    return this.primary.getKeyById(keyId) ?? this.fallback.getKeyById(keyId);
  }
}

/**
 * Factory: creates the default keyring provider for production use.
 * - If OPENCLAW_WRAP_KEY is set: returns EnvKeyringProvider (env takes priority)
 * - Otherwise: returns FileKeyringProvider (persistent across restarts)
 *
 * OS keyring support (Keychain / libsecret / Credential Vault) is a
 * follow-up PR via @napi-rs/keyring in optionalDependencies.
 */
export function createDefaultKeyringProvider(options?: {
  dir?: string;
  keyId?: string;
  preferOSKeyring?: boolean;
  osKeyringLoader?: () => NapiRsKeyringModule | null;
}): WrappingKeyProvider {
  if (process.env[ENV_KEY]) {
    return new EnvKeyringProvider();
  }
  const fileProvider = new FileKeyringProvider(options?.dir, options?.keyId);
  if (options?.preferOSKeyring !== false) {
    const osProvider = new OSKeyringProvider(
      "openclaw",
      options?.keyId,
      options?.osKeyringLoader ?? defaultKeyringLoader,
    );
    if (osProvider.isAvailable()) {
      return new CompositeKeyringProvider(osProvider, fileProvider);
    }
  }
  return fileProvider;
}
