// OS keyring provider (PQC whitepaper 2.2.5.B, M6.B).
//
// The real implementation uses @napi-rs/keyring (macOS Keychain,
// Windows Credential Manager, Linux Secret Service via D-Bus).
// The native dep is loaded dynamically via createRequire at
// construction time so a host that does not have it installed
// still loads this module — the failure shows up only when a
// caller actually tries to use an OsKeyring. Optional native deps
// (declared in package.json#optionalDependencies) handle the case
// where the binary cannot be loaded on a given platform.
//
// The KeyringProvider type is duplicated here (not imported) to
// avoid an ESM circular import: keyring-provider.ts static-imports
// this module, and the type would pull this file in at parse time.

import { createRequire } from "node:module";

export type ActiveWrappingKey = {
  key: Buffer;
  keyId: string;
};

export interface KeyringProvider {
  getActiveKey(): ActiveWrappingKey;
  getKeyById(keyId: string): Buffer | null;
}

/** Minimal shape of the @napi-rs/keyring Entry we use. Loaded
 *  dynamically so a missing native dep does not break module load. */
interface NapiKeyringEntry {
  getPassword(): string;
  setPassword(password: string): void;
  deletePassword(): void;
}

interface NapiKeyringModule {
  Entry: new (service: string, username: string) => NapiKeyringEntry;
}

/** Cached @napi-rs/keyring loader result. `null` after a load
 *  failure so we don't re-attempt the require on every construction
 *  (which would mask transient file-system errors as "module not
 *  installed" and bury the original cause). `undefined` means "not
 *  tried yet". */
let cachedKeyringModule: NapiKeyringModule | null | undefined = undefined;

function loadNapiKeyringModule(): NapiKeyringModule {
  if (cachedKeyringModule !== undefined) {
    return cachedKeyringModule ?? loadNapiKeyringModuleWithThrow();
  }
  try {
    const require = createRequire(import.meta.url);
    const mod = require("@napi-rs/keyring") as NapiKeyringModule;
    if (!mod || typeof mod.Entry !== "function") {
      throw new Error(
        "@napi-rs/keyring loaded but does not export Entry constructor",
      );
    }
    cachedKeyringModule = mod;
    return mod;
  } catch (cause) {
    cachedKeyringModule = null;
    return loadNapiKeyringModuleWithThrow(cause);
  }
}

function loadNapiKeyringModuleWithThrow(cause?: unknown): never {
  throw new Error(
    "OsKeyring: @napi-rs/keyring is not installed or its native binary " +
      "could not be loaded. Install it with `pnpm install` (or `npm install " +
      "@napi-rs/keyring`). On Linux you also need libsecret-1-0 (apt: " +
      "`libsecret-1-0`, rpm: `libsecret`) and a running Secret Service " +
      "(gnome-keyring, KWallet, KeePassXC, etc.). Until then use " +
      "{kind:\"file\"} or {kind:\"env\"} in the keyring config." +
      (cause instanceof Error ? ` Underlying error: ${cause.message}` : ""),
    cause instanceof Error ? { cause } : undefined,
  );
}

/** Decode a base64url-encoded 32-byte AES-256 key. Wire format is
 *  the same as FileKeyring / EnvKeyring so a key migrated from a
 *  file can be stored in the OS keyring verbatim. */
function decodeKeyMaterial(encoded: string, label: string): Buffer {
  if (typeof encoded !== "string" || encoded.length === 0) {
    throw new Error(`OsKeyring: ${label} must be a non-empty string`);
  }
  const key = Buffer.from(encoded, "base64url");
  if (key.length !== 32) {
    throw new Error(
      `OsKeyring: ${label} must decode to exactly 32 bytes (AES-256), got ${key.length}`,
    );
  }
  return key;
}

export class OsKeyring implements KeyringProvider {
  private readonly entry: NapiKeyringEntry;

  constructor(
    private readonly service: string,
    private readonly account: string,
    private readonly keyId: string = "os-keyring",
  ) {
    if (typeof service !== "string" || service.length === 0) {
      throw new Error("OsKeyring: service must be a non-empty string");
    }
    if (typeof account !== "string" || account.length === 0) {
      throw new Error("OsKeyring: account must be a non-empty string");
    }
    // Trigger the dynamic require now so construction fails fast on
    // a misconfigured host (rather than at the first wrap/unwrap).
    const mod = loadNapiKeyringModule();
    try {
      this.entry = new mod.Entry(service, account);
    } catch (cause) {
      throw new Error(
        `OsKeyring: failed to construct entry for service=${service} ` +
          `account=${account}. On Linux, is libsecret-1-0 installed and a ` +
          `Secret Service (gnome-keyring, KWallet, KeePassXC) running? ` +
          `Underlying error: ${cause instanceof Error ? cause.message : String(cause)}`,
        cause instanceof Error ? { cause } : undefined,
      );
    }
  }

  /** Read the active key. Returns the decoded 32-byte buffer plus
   *  the configured keyId. Throws if the entry does not exist or
   *  the stored password is malformed. */
  getActiveKey(): ActiveWrappingKey {
    let password: string;
    try {
      password = this.entry.getPassword();
    } catch (cause) {
      throw new Error(
        `OsKeyring: no entry found for service=${this.service} ` +
          `account=${this.account}. Run the migration script to seed ` +
          `the key (pqc-fork-scripts/migrate-oskeyring.mjs). ` +
          `Underlying error: ${cause instanceof Error ? cause.message : String(cause)}`,
        cause instanceof Error ? { cause } : undefined,
      );
    }
    return {
      key: decodeKeyMaterial(password, `os:${this.service}/${this.account}`),
      keyId: this.keyId,
    };
  }

  /** Look up a specific keyId. The OS keyring identifies entries
   *  by (service, account) only; we treat the requested keyId as
   *  the account name so rotation just stores a new entry with a
   *  different keyId. Returns null on "not found" so the composite
   *  can walk providers. */
  getKeyById(keyId: string): Buffer | null {
    if (keyId !== this.keyId) {
      // The active OsKeyring only "owns" one entry (the one it was
      // configured for). For historical keys from earlier rotations
      // use a separate OsKeyring configured with that keyId as the
      // account. The composite keyring in the env-driven factory
      // does not currently build a chain of OsKeyrings, so this
      // branch is the escape hatch for callers that need it.
      return null;
    }
    try {
      const password = this.entry.getPassword();
      return decodeKeyMaterial(password, `os:${this.service}/${this.account}`);
    } catch {
      return null;
    }
  }

  /** Migration / rotation helper: store a base64url-encoded
   *  32-byte AES-256 key in the OS keyring under
   *  (this.service, this.account). Not on the `KeyringProvider`
   *  interface — only callers that already know they are talking
   *  to an OsKeyring should call this. */
  setKeyBase64Url(base64urlKey: string): void {
    decodeKeyMaterial(base64urlKey, "setKeyBase64Url input");
    this.entry.setPassword(base64urlKey);
  }

  /** Migration / rotation helper: delete the entry. */
  deleteKey(): void {
    try {
      this.entry.deletePassword();
    } catch (cause) {
      throw new Error(
        `OsKeyring: failed to delete entry for service=${this.service} ` +
          `account=${this.account}. ` +
          `Underlying error: ${cause instanceof Error ? cause.message : String(cause)}`,
        cause instanceof Error ? { cause } : undefined,
      );
    }
  }

  /** Test-only inspector; lets the composite know the OS variant
   *  owns the (service, account) slot so a rotation can rewrite the
   *  same slot. */
  describe(): { service: string; account: string; keyId: string } {
    return { service: this.service, account: this.account, keyId: this.keyId };
  }

  /** Test-only hook: clear the cached @napi-rs/keyring module so
   *  the next construction re-attempts the require. Production
   *  code should not need this. */
  static __resetNapiCacheForTests(): void {
    cachedKeyringModule = undefined;
  }
}
