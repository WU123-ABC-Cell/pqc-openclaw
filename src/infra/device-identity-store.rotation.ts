import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import { isDeepStrictEqual } from "node:util";
import type { Selectable } from "kysely";
import {
  CompositeKeyring,
  FileKeyring,
  preflightWrappingKeyProviderReadOnly,
} from "../security/keyring-provider.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";
import { rotateWrappingKey } from "../security/wrap-key-rotation.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import {
  closeOpenClawStateDatabaseByPath,
  getOpenClawStateDatabaseIfOpen,
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import {
  DeviceIdentityStorageError,
  identityWrappingContext,
  type StoredDeviceIdentity,
} from "./device-identity-store.crypto.js";
import { inspectStoredIdentityPopulation } from "./device-identity-store.wrapping-upgrade.js";
import { activeIdentityWriteGeneration } from "./device-identity-write-generation.js";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "./kysely-sync.js";
import { readSqliteUserVersion } from "./sqlite-user-version.js";

type Row = Selectable<DB["device_identities"]>;
type ReadRow = Parameters<typeof inspectStoredIdentityPopulation>[1];

function comparable(rows: Row[]): Row[] {
  return rows.map((row) => ({
    ...row,
    mldsa_private_key_wrapped:
      row.mldsa_private_key_wrapped == null ? null : Buffer.from(row.mldsa_private_key_wrapped),
  }));
}

function sameKey(expected: Buffer, actual: Buffer | null): boolean {
  return Boolean(actual && actual.length === expected.length && timingSafeEqual(expected, actual));
}

/** Re-wrap every verified Node row; the caller has provisioned independent old/new keys. */
export function rotateStoredIdentityWriteGeneration(params: {
  databasePath: string;
  options: OpenClawStateDatabaseOptions;
  receiptId: string;
  targetKeyId: string;
  oldKeyring: WrappingKeyProvider;
  newKeyring: WrappingKeyProvider;
  readRow: ReadRow;
  isKeyAccessError: (error: unknown) => boolean;
}): { generation: number; replayed: false } {
  if (!fs.existsSync(params.databasePath)) {
    throw new DeviceIdentityStorageError("Identity rotation requires an existing state database.");
  }
  if (getOpenClawStateDatabaseIfOpen({ path: params.databasePath })) {
    throw new DeviceIdentityStorageError(
      "Stop the local state runtime before rotating identity writes; a shared handle is open.",
    );
  }
  const oldPreflight = preflightWrappingKeyProviderReadOnly(params.oldKeyring);
  const newPreflight = preflightWrappingKeyProviderReadOnly(params.newKeyring);
  if (oldPreflight.status !== "verified" || newPreflight.status !== "verified") {
    throw new DeviceIdentityStorageError(
      "Identity rotation requires verified old and new keyrings.",
    );
  }
  const oldActive = params.oldKeyring.getActiveKey();
  const newActive = params.newKeyring.getActiveKey();
  if (
    !params.targetKeyId ||
    newActive.keyId !== params.targetKeyId ||
    newActive.keyId === oldActive.keyId ||
    timingSafeEqual(newActive.key, oldActive.key)
  ) {
    throw new DeviceIdentityStorageError(
      "Identity rotation requires a distinct new key ID and key.",
    );
  }
  const oldKey = Buffer.from(oldActive.key);
  const newKey = Buffer.from(newActive.key);
  const historicalKeys = new Map<string, Buffer>();
  try {
    const snapshot = inspectStoredIdentityPopulation(
      { ...params.options, path: params.databasePath, wrappingKeyProvider: params.oldKeyring },
      params.readRow,
      params.isKeyAccessError,
    );
    if (snapshot.rows.length === 0) {
      throw new DeviceIdentityStorageError(
        "Identity rotation requires a nonempty identity population.",
      );
    }
    if (snapshot.report.some((row) => row.status !== "verified")) {
      throw new DeviceIdentityStorageError(
        "Identity rotation requires every row to be verified; repair legacy, damaged or native rows first.",
      );
    }
    const planned = new Map<string, Row>();
    for (const row of snapshot.rows) {
      if (
        !Number.isSafeInteger(row.write_generation) ||
        row.write_generation <= 0 ||
        !Number.isSafeInteger(row.write_revision) ||
        row.write_revision < 0 ||
        !Number.isSafeInteger(row.write_revision + 1)
      ) {
        throw new DeviceIdentityStorageError("Identity rotation found invalid row write metadata.");
      }
      const historicalId = row.mldsa_private_key_wrap_key_id;
      if (!historicalId || historicalId === params.targetKeyId || !row.mldsa_private_key_wrapped) {
        throw new DeviceIdentityStorageError(
          "Identity rotation found an invalid or colliding row key ID.",
        );
      }
      if (!historicalKeys.has(historicalId)) {
        const historical = params.oldKeyring.getKeyById(historicalId);
        if (
          !historical ||
          historical.length !== 32 ||
          !sameKey(historical, params.newKeyring.getKeyById(historicalId)) ||
          sameKey(newKey, historical)
        ) {
          throw new DeviceIdentityStorageError(
            "Identity rotation requires every historical key in the new keyring.",
          );
        }
        historicalKeys.set(historicalId, Buffer.from(historical));
      }
      const original = params.readRow(row, row.identity_key, params.oldKeyring);
      const rotated = rotateWrappingKey({
        stored: {
          privateKeyPem: original.privateKeyPem,
          mldsaPrivateKeyWrapped: original.mldsaPrivateKeyWrapped,
          mldsaPrivateKeyWrapKeyId: original.mldsaPrivateKeyWrapKeyId,
        },
        oldKeyring: params.oldKeyring,
        newKeyring: params.newKeyring,
        associatedData: identityWrappingContext(
          row.identity_key,
          row.device_id,
          original.publicKeyPem,
        ),
      });
      const next: Row = {
        ...row,
        mldsa_private_key_wrapped: Buffer.from(rotated.mldsaPrivateKeyWrapped),
        mldsa_private_key_wrap_key_id: rotated.mldsaPrivateKeyWrapKeyId,
        write_generation: 0,
        write_revision: row.write_revision + 1,
        updated_at_ms: Date.now(),
      };
      const verified: StoredDeviceIdentity = params.readRow(
        next,
        row.identity_key,
        params.newKeyring,
      );
      if (
        verified.privateKeyPem !== original.privateKeyPem ||
        verified.publicKeyPem !== original.publicKeyPem ||
        verified.deviceId !== original.deviceId ||
        rotated.mldsaPrivateKeyWrapKeyId !== params.targetKeyId ||
        !Number.isSafeInteger(next.write_revision)
      ) {
        throw new DeviceIdentityStorageError("Identity rotation could not verify a planned row.");
      }
      planned.set(row.identity_key, next);
    }
    try {
      return runOpenClawStateWriteTransaction(
        ({ db }) => {
          if (readSqliteUserVersion(db) !== 7) {
            throw new DeviceIdentityStorageError(
              "Identity rotation requires an activated v7 database.",
            );
          }
          const owner = activeIdentityWriteGeneration(db);
          if (
            !owner ||
            owner.newWriteKeyId !== oldActive.keyId ||
            !Number.isSafeInteger(owner.generation + 1)
          ) {
            throw new DeviceIdentityStorageError(
              "Identity rotation owner changed or generation is exhausted.",
            );
          }
          const rows = executeSqliteQuerySync(
            db,
            getNodeSqliteKysely<Pick<DB, "device_identities">>(db)
              .selectFrom("device_identities")
              .selectAll()
              .orderBy("identity_key"),
          ).rows;
          if (!isDeepStrictEqual(comparable(rows), comparable(snapshot.rows))) {
            throw new DeviceIdentityStorageError(
              "Identity population changed during rotation planning; retry.",
            );
          }
          if (
            rows.some(
              (row) =>
                row.write_generation !== owner.generation ||
                !Number.isSafeInteger(row.write_revision) ||
                row.write_revision < 0,
            )
          ) {
            throw new DeviceIdentityStorageError(
              "Identity rotation found rows outside the active generation.",
            );
          }
          const oldCurrent = params.oldKeyring.getActiveKey();
          const newCurrent = params.newKeyring.getActiveKey();
          if (
            oldCurrent.keyId !== oldActive.keyId ||
            !sameKey(oldKey, oldCurrent.key) ||
            newCurrent.keyId !== params.targetKeyId ||
            !sameKey(newKey, newCurrent.key)
          ) {
            throw new DeviceIdentityStorageError(
              "Identity rotation key changed during planning; retry.",
            );
          }
          for (const [id, historical] of historicalKeys) {
            if (
              !sameKey(historical, params.oldKeyring.getKeyById(id)) ||
              !sameKey(historical, params.newKeyring.getKeyById(id))
            ) {
              throw new DeviceIdentityStorageError(
                "Identity rotation historical key changed during planning; retry.",
              );
            }
          }
          // Cached provider bytes alone do not prove a prepared file still exists.
          if (params.newKeyring instanceof FileKeyring) {
            params.newKeyring.assertCachedKeyStillInstalled();
          } else if (params.newKeyring instanceof CompositeKeyring) {
            params.newKeyring.assertActiveFileKeyStillInstalled();
          }
          const nextGeneration = owner.generation + 1;
          db.prepare(
            "UPDATE identity_write_generation SET generation = ?, new_write_key_id = ? WHERE singleton = 1",
          ).run(nextGeneration, params.targetKeyId);
          const update = db.prepare(`UPDATE device_identities SET
            mldsa_private_key_wrapped = ?, mldsa_private_key_wrap_key_id = ?,
            write_generation = ?, write_revision = ?, updated_at_ms = ?
            WHERE identity_key = ? AND write_generation = ? AND write_revision = ?`);
          for (const row of rows) {
            const next = planned.get(row.identity_key);
            if (!next) {
              throw new DeviceIdentityStorageError("Identity rotation plan omitted a row.");
            }
            next.write_generation = nextGeneration;
            const result = update.run(
              next.mldsa_private_key_wrapped,
              params.targetKeyId,
              nextGeneration,
              next.write_revision,
              next.updated_at_ms,
              row.identity_key,
              row.write_generation,
              row.write_revision,
            );
            if (result.changes !== 1) {
              throw new DeviceIdentityStorageError("Identity rotation lost a row while writing.");
            }
          }
          db.prepare(
            "INSERT INTO identity_write_receipts (receipt_id, generation, new_write_key_id) VALUES (?, ?, ?)",
          ).run(params.receiptId, nextGeneration, params.targetKeyId);
          const after = executeSqliteQuerySync(
            db,
            getNodeSqliteKysely<Pick<DB, "device_identities">>(db)
              .selectFrom("device_identities")
              .selectAll()
              .orderBy("identity_key"),
          ).rows;
          if (
            !isDeepStrictEqual(
              comparable(after),
              comparable(rows.map((row) => planned.get(row.identity_key)!)),
            )
          ) {
            throw new DeviceIdentityStorageError(
              "Identity rotation did not persist the complete population.",
            );
          }
          for (const row of after) {
            const identity = params.readRow(row, row.identity_key, params.newKeyring);
            if (
              row.write_generation !== nextGeneration ||
              row.mldsa_private_key_wrap_key_id !== params.targetKeyId ||
              !identity.privateKeyPem
            ) {
              throw new DeviceIdentityStorageError(
                "Identity rotation could not verify a committed row.",
              );
            }
          }
          // The final row read can itself observe a cached key after the slot
          // changes. Recheck the persisted slot at the last precommit boundary.
          if (params.newKeyring instanceof FileKeyring) {
            params.newKeyring.assertCachedKeyStillInstalled();
          } else if (params.newKeyring instanceof CompositeKeyring) {
            params.newKeyring.assertActiveFileKeyStillInstalled();
          }
          return { generation: nextGeneration, replayed: false };
        },
        { ...params.options, path: params.databasePath },
        { operationLabel: "device-identity.rotate-write-generation" },
      );
    } finally {
      closeOpenClawStateDatabaseByPath(params.databasePath);
    }
  } finally {
    oldKey.fill(0);
    newKey.fill(0);
    for (const key of historicalKeys.values()) {
      key.fill(0);
    }
  }
}
