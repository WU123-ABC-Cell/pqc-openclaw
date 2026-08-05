// PQC step 2.3.5.C: wrap-key rotation helpers.
//
// Pure functions: callers own the database transaction. State-migration glue
// (which iterates device_identities rows) lives in
// src/infra/state-migrations.rotate-wrapping-key.ts.

import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  unwrapSecret,
  wrapSecret,
  type WrappingKeyProvider,
} from "./secret-wrapping.js";

export interface WrappedKeyPair {
  /** base64url-encoded WrappedSecret (or null if not wrapped). */
  wrapped: string | null;
  /** key id used to wrap (or null if not wrapped). */
  wrapKeyId: string | null;
}

export interface RewrapResult extends WrappedKeyPair {
  /** True iff the row was actually re-wrapped under the new key. */
  changed: boolean;
}

/**
 * Re-wrap a stored (wrapped, wrapKeyId) pair under a new key.
 *
 * - If both inputs are null: returns the same nulls (nothing to re-wrap).
 * - If the existing wrapKeyId already matches newKeyId and no oldProvider
 *   is given: returns unchanged.
 * - Otherwise: unwrap with the old provider, then wrap with the new provider.
 *   If no oldProvider is given, the new provider is also used for unwrap
 *   (this works when the key id has not changed but the caller wants to
 *   refresh the IV/authTag).
 */
export function rewrapStoredSecret(
  stored: WrappedKeyPair,
  newProvider: WrappingKeyProvider,
  newKeyId: string,
  oldProvider?: WrappingKeyProvider,
): RewrapResult {
  const { wrapped, wrapKeyId } = stored;
  if (wrapped === null || wrapKeyId === null) {
    return { wrapped, wrapKeyId, changed: false };
  }
  if (wrapKeyId === newKeyId && oldProvider === undefined) {
    return { wrapped, wrapKeyId, changed: false };
  }
  const providerForUnwrap = oldProvider ?? newProvider;
  const plaintext = unwrapSecret(
    deserializeWrappedSecret(wrapped),
    providerForUnwrap,
  );
  const fresh = wrapSecret(plaintext, newProvider);
  return {
    wrapped: serializeWrappedSecret(fresh),
    wrapKeyId: newKeyId,
    changed: true,
  };
}

/** Re-wrap a list of stored pairs and return the count actually changed. */
export function rewrapAll(
  rows: WrappedKeyPair[],
  newProvider: WrappingKeyProvider,
  newKeyId: string,
  oldProvider?: WrappingKeyProvider,
): { results: RewrapResult[]; rotated: number } {
  let rotated = 0;
  const results = rows.map((row) => {
    const r = rewrapStoredSecret(row, newProvider, newKeyId, oldProvider);
    if (r.changed) rotated++;
    return r;
  });
  return { results, rotated };
}

/**
 * A single device_identities row relevant for wrap-key rotation.
 * Both the legacy Ed25519 wrap and the ML-DSA-65 wrap are present so
 * callers can rewrap both keys in one pass.
 */
export interface DeviceIdentityWrapRow {
  identity_key: string;
  private_key_wrapped: string | null;
  private_key_wrap_key_id: string | null;
  mldsa_private_key_wrapped: string | null;
  mldsa_private_key_wrap_key_id: string | null;
}

/** Per-row output of `rewrapDeviceIdentityRow`. */
export interface RewrappedDeviceIdentity {
  identity_key: string;
  ed25519: RewrapResult;
  mldsa: RewrapResult;
  changed: boolean;
}

/** Re-wrap both Ed25519 and ML-DSA-65 wrap columns for a single row. */
export function rewrapDeviceIdentityRow(
  row: DeviceIdentityWrapRow,
  newProvider: WrappingKeyProvider,
  newKeyId: string,
  oldProvider?: WrappingKeyProvider,
): RewrappedDeviceIdentity {
  const ed25519 = rewrapStoredSecret(
    { wrapped: row.private_key_wrapped, wrapKeyId: row.private_key_wrap_key_id },
    newProvider,
    newKeyId,
    oldProvider,
  );
  const mldsa = rewrapStoredSecret(
    { wrapped: row.mldsa_private_key_wrapped, wrapKeyId: row.mldsa_private_key_wrap_key_id },
    newProvider,
    newKeyId,
    oldProvider,
  );
  return {
    identity_key: row.identity_key,
    ed25519,
    mldsa,
    changed: ed25519.changed || mldsa.changed,
  };
}
