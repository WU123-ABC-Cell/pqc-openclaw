// PQC step 2.3.5.C: rotate wrap-keys for all device_identities rows.
//
// Iterates every row, re-wraps both the Ed25519 private_key_pem and the
// ML-DSA-65 mldsa_private_key_pem under a new key id, and writes the new
// wrap columns back. The legacy plaintext columns are left untouched for
// backward compatibility with the 2.3 column-additive migration.
//
// Runs inside runOpenClawStateWriteTransaction (synchronous, immediate) so
// all rows are rotated atomically.

import { runOpenClawStateWriteTransaction, type OpenClawStateDatabaseOptions } from "../state/openclaw-state-db.js";
import {
  rewrapDeviceIdentityRow,
  type DeviceIdentityWrapRow,
} from "../security/rotate-wrapping-key.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";

export interface RotateDeviceIdentityWrappingKeyOptions extends OpenClawStateDatabaseOptions {
  /** Provider that yields the new active key. */
  newProvider: WrappingKeyProvider;
  /** The new key id (must match newProvider.getActiveKey().keyId). */
  newKeyId: string;
  /** Optional: provider to use for unwrapping existing rows. Defaults to newProvider. */
  oldProvider?: WrappingKeyProvider;
  /** Optional: override the clock for tests. */
  nowMs?: number;
}

export interface RotateDeviceIdentityWrappingKeyResult {
  /** Number of rows whose wrap columns actually changed. */
  rotatedRows: number;
  /** Set of distinct wrap key ids that were replaced. */
  fromKeyIds: Set<string>;
  /** The new key id. */
  toKeyId: string;
}

const SELECT_SQL = [
  "SELECT",
  "  identity_key,",
  "  private_key_wrapped, private_key_wrap_key_id,",
  "  mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id",
  "FROM device_identities",
].join("\n");

const UPDATE_SQL = [
  "UPDATE device_identities SET",
  "  private_key_wrapped = ?,",
  "  private_key_wrap_key_id = ?,",
  "  mldsa_private_key_wrapped = ?,",
  "  mldsa_private_key_wrap_key_id = ?,",
  "  updated_at_ms = ?",
  "WHERE identity_key = ?",
].join("\n");

export function rotateDeviceIdentityWrappingKey(
  options: RotateDeviceIdentityWrappingKeyOptions,
): RotateDeviceIdentityWrappingKeyResult {
  // Spread our own fields away; rest are DB options.
  const { newProvider: _np, newKeyId: _nk, oldProvider: _op, nowMs: _nm, ...dbOptions } = options;
  void _np; void _nk; void _op; void _nm;
  return runOpenClawStateWriteTransaction(
    (database) => {
      const rows = database.db.prepare(SELECT_SQL).all() as DeviceIdentityWrapRow[];

      const fromKeyIds = new Set<string>();
      let rotatedRows = 0;
      const now = options.nowMs ?? Date.now();

      const update = database.db.prepare(UPDATE_SQL);

      for (const row of rows) {
        const rewrapped = rewrapDeviceIdentityRow(
          row,
          options.newProvider,
          options.newKeyId,
          options.oldProvider,
        );
        if (!rewrapped.changed) continue;

        if (row.private_key_wrap_key_id && row.private_key_wrap_key_id !== options.newKeyId) {
          fromKeyIds.add(row.private_key_wrap_key_id);
        }
        if (row.mldsa_private_key_wrap_key_id && row.mldsa_private_key_wrap_key_id !== options.newKeyId) {
          fromKeyIds.add(row.mldsa_private_key_wrap_key_id);
        }

        update.run(
          rewrapped.ed25519.wrapped,
          rewrapped.ed25519.wrapKeyId,
          rewrapped.mldsa.wrapped,
          rewrapped.mldsa.wrapKeyId,
          now,
          row.identity_key,
        );
        rotatedRows++;
      }

      return { rotatedRows, fromKeyIds, toKeyId: options.newKeyId };
    },
    dbOptions,
    { operationLabel: "state.rotate-wrapping-key" },
  );
}
