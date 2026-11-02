import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { preflightWrappingKeyProviderReadOnly } from "../security/keyring-provider.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";
import { activateIdentityWriteSchemaInTransaction } from "../state/openclaw-state-db-identity-activation.js";
import { withExistingOpenClawStateDatabaseReadOnly } from "../state/openclaw-state-db-readonly.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import {
  closeOpenClawStateDatabaseByPath,
  getOpenClawStateDatabaseIfOpen,
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import { DeviceIdentityStorageError } from "./device-identity-store.crypto.js";
import { inspectStoredIdentityPopulation } from "./device-identity-store.wrapping-upgrade.js";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "./kysely-sync.js";
import { readSqliteUserVersion } from "./sqlite-user-version.js";

type Options = OpenClawStateDatabaseOptions & { wrappingKeyProvider?: WrappingKeyProvider };
type ReadRow = Parameters<typeof inspectStoredIdentityPopulation>[1];

/** Resolve an ambiguous database commit without opening a keyring.
 * The result is a SQLite snapshot, not proof that the external key is still available. */
export function readIdentityWriteReceipt(
  databasePath: string,
  receiptId: string,
): {
  generation: number;
  newWriteKeyId: string;
  databaseState: "current" | "superseded";
} | null {
  if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(receiptId)) {
    throw new DeviceIdentityStorageError("Identity write change needs a stable receipt ID.");
  }
  return (
    withExistingOpenClawStateDatabaseReadOnly(
      ({ db }) => {
        if (readSqliteUserVersion(db) !== 7) {
          return null;
        }
        // One statement observes receipt and owner from the same SQLite snapshot.
        const receipt = db
          .prepare(`SELECT receipt.generation, receipt.new_write_key_id,
                   owner.generation AS owner_generation,
                   owner.new_write_key_id AS owner_key_id
                   FROM identity_write_receipts AS receipt
                   LEFT JOIN identity_write_generation AS owner ON owner.singleton = 1
                   WHERE receipt.receipt_id = ?`)
          .get(receiptId) as
          | {
              generation?: unknown;
              new_write_key_id?: unknown;
              owner_generation?: unknown;
              owner_key_id?: unknown;
            }
          | undefined;
        if (!receipt) {
          return null;
        }
        if (
          !Number.isSafeInteger(receipt.generation) ||
          Number(receipt.generation) <= 0 ||
          typeof receipt.new_write_key_id !== "string" ||
          receipt.new_write_key_id.length === 0 ||
          !Number.isSafeInteger(receipt.owner_generation) ||
          Number(receipt.owner_generation) < Number(receipt.generation) ||
          typeof receipt.owner_key_id !== "string" ||
          receipt.owner_key_id.length === 0 ||
          (receipt.owner_generation === receipt.generation &&
            receipt.owner_key_id !== receipt.new_write_key_id)
        ) {
          throw new DeviceIdentityStorageError("Identity write receipt is inconsistent.");
        }
        return {
          generation: Number(receipt.generation),
          newWriteKeyId: receipt.new_write_key_id,
          databaseState: receipt.owner_generation === receipt.generation ? "current" : "superseded",
        };
      },
      { path: databasePath },
    ) ?? null
  );
}

/** Offline, operator-triggered first activation; the stable receipt resolves unknown commits. */
export function activateStoredIdentityWriteGeneration(
  databasePath: string,
  options: Options,
  receiptId: string,
  readRow: ReadRow,
  isKeyAccessError: (error: unknown) => boolean,
): { generation: 1; replayed: boolean } {
  if (!/^[A-Za-z0-9._:-]{1,128}$/u.test(receiptId)) {
    throw new DeviceIdentityStorageError("Identity write activation needs a stable receipt ID.");
  }
  if (!fs.existsSync(databasePath)) {
    throw new DeviceIdentityStorageError(
      "Identity write activation requires an existing state database.",
    );
  }
  if (getOpenClawStateDatabaseIfOpen({ path: databasePath })) {
    throw new DeviceIdentityStorageError(
      "Stop the local state runtime before activating identity writes; a shared handle is open.",
    );
  }
  const provider = options.wrappingKeyProvider;
  if (!provider) {
    throw new DeviceIdentityStorageError(
      "Identity write activation requires a wrapping key provider.",
    );
  }
  const providerPreflight = preflightWrappingKeyProviderReadOnly(provider);
  if (providerPreflight.status !== "verified") {
    throw new DeviceIdentityStorageError(
      `Identity write activation wrapping provider is not verified: ${providerPreflight.reason}.`,
    );
  }
  const active = provider.getActiveKey();
  const key = Buffer.from(active.key);
  try {
    const lookup = provider.getKeyById(active.keyId);
    if (
      !active.keyId ||
      key.length !== 32 ||
      !lookup ||
      lookup.length !== key.length ||
      !timingSafeEqual(key, lookup)
    ) {
      throw new DeviceIdentityStorageError(
        "Identity write activation needs a consistent active wrapping key.",
      );
    }
    const snapshot = inspectStoredIdentityPopulation(
      { ...options, path: databasePath },
      readRow,
      isKeyAccessError,
    );
    if (snapshot.rows.length === 0) {
      throw new DeviceIdentityStorageError(
        "Identity write activation requires a nonempty identity population.",
      );
    }
    const unverified = snapshot.report.filter((row) => row.status !== "verified");
    if (unverified.length) {
      throw new DeviceIdentityStorageError(
        `Identity write activation requires every row to be verified; ${unverified.length} need Doctor or native verification.`,
      );
    }
    try {
      return runOpenClawStateWriteTransaction(
        ({ db, path: pathname }) => {
          const version = readSqliteUserVersion(db);
          if (version === 7) {
            const owner = db
              .prepare(
                "SELECT generation, new_write_key_id FROM identity_write_generation WHERE singleton = 1",
              )
              .get() as { generation?: unknown; new_write_key_id?: unknown } | undefined;
            const receipt = db
              .prepare(
                "SELECT generation, new_write_key_id FROM identity_write_receipts WHERE receipt_id = ?",
              )
              .get(receiptId) as { generation?: unknown; new_write_key_id?: unknown } | undefined;
            if (owner) {
              if (
                owner.generation === 1 &&
                owner.new_write_key_id === active.keyId &&
                receipt?.generation === 1 &&
                receipt.new_write_key_id === active.keyId
              ) {
                return { generation: 1, replayed: true };
              }
              throw new DeviceIdentityStorageError(
                "Identity write generation is already active under a different receipt or key.",
              );
            }
          }
          if (version !== 6 && version !== 7) {
            throw new DeviceIdentityStorageError(
              "Identity write activation requires schema v6 or dormant v7.",
            );
          }
          const rows = executeSqliteQuerySync(
            db,
            getNodeSqliteKysely<Pick<DB, "device_identities">>(db)
              .selectFrom("device_identities")
              .selectAll()
              .orderBy("identity_key"),
          ).rows;
          if (!isDeepStrictEqual(rows, snapshot.rows)) {
            throw new DeviceIdentityStorageError(
              "Identity population changed during activation planning; retry.",
            );
          }
          const current = provider.getActiveKey();
          const currentLookup = provider.getKeyById(active.keyId);
          if (
            current.keyId !== active.keyId ||
            current.key.length !== key.length ||
            !timingSafeEqual(current.key, key) ||
            !currentLookup ||
            currentLookup.length !== key.length ||
            !timingSafeEqual(currentLookup, key)
          ) {
            throw new DeviceIdentityStorageError(
              "Wrapping key changed during activation planning; retry.",
            );
          }
          activateIdentityWriteSchemaInTransaction(db, pathname, receiptId, active.keyId);
          return { generation: 1, replayed: false };
        },
        { env: options.env, path: databasePath },
        { operationLabel: "device-identity.activate-write-generation" },
      );
    } finally {
      // DDL invalidates prepared statements; never hand the old cached handle back to runtime.
      closeOpenClawStateDatabaseByPath(databasePath);
    }
  } finally {
    key.fill(0);
  }
}
