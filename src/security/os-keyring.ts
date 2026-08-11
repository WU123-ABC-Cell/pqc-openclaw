// OS keyring provider (PQC whitepaper 2.2.5.B).
//
// The full implementation uses @napi-rs/keyring (macOS Keychain,
// Windows Credential Manager, Linux Secret Service via D-Bus). That
// native dep is deliberately NOT added in this commit so the rest of
// the M6 surface (file / env / composite) compiles and tests run on
// any host without a native module. M6.B will land the real provider
// once @napi-rs/keyring's native binary is verified to load on the
// fork's Node 22 LTS runtime.
//
// Until then, this stub refuses to construct so a misconfigured
// `{kind: "os"}` config fails at boot with a clear message instead
// of silently returning an empty key.
//
// The KeyringProvider type is duplicated here (not imported) to avoid
// an ESM circular import: keyring-provider.ts dynamic-requires this
// module for the `{kind:"os"}` config branch, and importing the
// type would pull this file in at static-parse time.

export type ActiveWrappingKey = {
  key: Buffer;
  keyId: string;
};

export interface KeyringProvider {
  getActiveKey(): ActiveWrappingKey;
  getKeyById(keyId: string): Buffer | null;
}

export class OsKeyring implements KeyringProvider {
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
  }

  getActiveKey(): ActiveWrappingKey {
    throw new Error(
      "OsKeyring: not implemented in this build. M6.B will add @napi-rs/keyring " +
        "as an optional native dependency; until then use {kind:\"file\"} or " +
        "{kind:\"env\"} in the keyring config.",
    );
  }

  getKeyById(_keyId: string): Buffer | null {
    throw new Error(
      "OsKeyring: not implemented in this build. M6.B will add @napi-rs/keyring.",
    );
  }

  /** Test-only inspector; lets the composite know the OS variant
   *  owns the (service, account) slot so a rotation can rewrite the
   *  same slot. */
  describe(): { service: string; account: string; keyId: string } {
    return { service: this.service, account: this.account, keyId: this.keyId };
  }
}
