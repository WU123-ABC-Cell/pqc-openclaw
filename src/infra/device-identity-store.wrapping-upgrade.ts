import { timingSafeEqual } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { Selectable } from "kysely";
import {
  serializeWrappedSecret,
  wrapSecret,
  type WrappingKeyProvider,
} from "../security/secret-wrapping.js";
import { withExistingOpenClawStateDatabaseReadOnly } from "../state/openclaw-state-db-readonly.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import {
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import {
  DeviceIdentityStorageError,
  generateStoredDeviceIdentity,
  identityWrappingContext,
  type StoredDeviceIdentity,
} from "./device-identity-store.crypto.js";
import { inspectIdentityPopulationRow } from "./device-identity-store.population-preflight.js";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "./kysely-sync.js";
import { decodeMlDsa65SecretKey } from "./mldsa65-key-storage.js";

type Row = Selectable<DB["device_identities"]>;
type ReadRow = Parameters<typeof inspectIdentityPopulationRow>[2];
type Options = OpenClawStateDatabaseOptions & { wrappingKeyProvider?: WrappingKeyProvider };

function comparable(rows: Row[]) {
  return rows
    .map((row) => ({
      ...row,
      mldsa_private_key_wrapped:
        row.mldsa_private_key_wrapped == null ? null : Buffer.from(row.mldsa_private_key_wrapped),
    }))
    .toSorted((a, b) =>
      a.identity_key < b.identity_key ? -1 : a.identity_key > b.identity_key ? 1 : 0,
    );
}

export function inspectStoredIdentityPopulation(
  options: Options,
  readRow: ReadRow,
  isKeyAccessError: (error: unknown) => boolean,
) {
  return (
    withExistingOpenClawStateDatabaseReadOnly(({ db }) => {
      const { rows } = executeSqliteQuerySync(
        db,
        getNodeSqliteKysely<DB>(db)
          .selectFrom("device_identities")
          .selectAll()
          .orderBy("identity_key"),
      );
      return {
        rows,
        report: rows.map((row) =>
          inspectIdentityPopulationRow(row, options.wrappingKeyProvider, readRow, isKeyAccessError),
        ),
      };
    }, options) ?? { rows: [], report: [] }
  );
}

/** Doctor-only: plan outside SQLite's write transaction, then compare the complete census and commit atomically. */
export function upgradeStoredIdentityPopulation(
  options: Options,
  readRow: ReadRow,
  isKeyAccessError: (error: unknown) => boolean,
  encodeRow: (key: string, identity: StoredDeviceIdentity, updatedAt: number) => Row,
  params: { createMissingPrimary?: boolean } = {},
) {
  const snapshot = inspectStoredIdentityPopulation(options, readRow, isKeyAccessError);
  const blocked = snapshot.report.filter((row) => row.status === "blocked");
  const pendingNative = snapshot.report
    .filter((row) => row.status === "needs-native-verification")
    .map((row) => row.identityKey);
  if (blocked.length) {
    return { upgraded: [], blocked, pendingNative, createdPrimary: false };
  }
  const createPrimary =
    params.createMissingPrimary === true &&
    !snapshot.rows.some((row) => row.identity_key === "primary");
  const candidates = snapshot.report.filter((row) => row.status === "needs-upgrade");
  if (!candidates.length && !createPrimary) {
    return { upgraded: [], blocked, pendingNative, createdPrimary: false };
  }
  const provider = options.wrappingKeyProvider;
  if (!provider) {
    throw new DeviceIdentityStorageError(
      "Doctor population upgrade requires a wrapping key provider.",
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
        "Doctor population upgrade requires a consistent active wrapping key.",
      );
    }
    const frozen: WrappingKeyProvider = {
      getActiveKey: () => ({ keyId: active.keyId, key }),
      getKeyById: (id) => (id === active.keyId ? key : provider.getKeyById(id)),
    };
    const planned = new Map<string, Row>();
    let newPrimary: Row | undefined;
    if (createPrimary) {
      const identity = generateStoredDeviceIdentity(Date.now(), frozen);
      newPrimary = encodeRow("primary", identity, identity.createdAtMs);
      if (
        inspectIdentityPopulationRow(newPrimary, frozen, readRow, isKeyAccessError).status !==
        "verified"
      ) {
        throw new DeviceIdentityStorageError("Doctor could not verify the new primary identity.");
      }
    }
    for (const candidate of candidates) {
      const row = snapshot.rows.find((entry) => entry.identity_key === candidate.identityKey)!;
      const identity = readRow(row, row.identity_key, provider, true);
      const raw = decodeMlDsa65SecretKey(identity.privateKeyPem);
      const plaintext = Buffer.from(raw);
      try {
        const wrapped = wrapSecret(
          plaintext,
          frozen,
          identityWrappingContext(row.identity_key, identity.deviceId, identity.publicKeyPem),
        );
        const encoded = encodeRow(
          row.identity_key,
          {
            ...identity,
            mldsaPrivateKeyPem: null,
            mldsaPrivateKeyWrapped: serializeWrappedSecret(wrapped),
            mldsaPrivateKeyWrapKeyId: wrapped.keyId,
          },
          Date.now(),
        );
        const checked = inspectIdentityPopulationRow(encoded, frozen, readRow, isKeyAccessError);
        if (checked.status !== "verified") {
          throw new DeviceIdentityStorageError(
            "Doctor could not verify a planned identity upgrade.",
          );
        }
        planned.set(row.identity_key, encoded);
      } finally {
        raw.fill(0);
        plaintext.fill(0);
      }
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
        "Wrapping key changed during Doctor population planning; retry.",
      );
    }
    runOpenClawStateWriteTransaction(
      ({ db }) => {
        const sql = getNodeSqliteKysely<DB>(db);
        const { rows } = executeSqliteQuerySync(
          db,
          sql.selectFrom("device_identities").selectAll().orderBy("identity_key"),
        );
        if (!isDeepStrictEqual(comparable(rows), comparable(snapshot.rows))) {
          throw new DeviceIdentityStorageError(
            "Identity population changed during Doctor planning; retry.",
          );
        }
        for (const [identityKey, row] of planned) {
          executeSqliteQuerySync(
            db,
            sql.updateTable("device_identities").set(row).where("identity_key", "=", identityKey),
          );
        }
        if (newPrimary) {
          executeSqliteQuerySync(db, sql.insertInto("device_identities").values(newPrimary));
        }
        const after = executeSqliteQuerySync(
          db,
          sql.selectFrom("device_identities").selectAll().orderBy("identity_key"),
        ).rows;
        const expected = snapshot.rows.map((row) => planned.get(row.identity_key) ?? row);
        if (newPrimary) {
          expected.push(newPrimary);
        }
        if (!isDeepStrictEqual(comparable(after), comparable(expected))) {
          throw new DeviceIdentityStorageError(
            "Identity population was not durable after Doctor upgrade.",
          );
        }
      },
      options,
      { operationLabel: "device-identity.doctor-population-wrap" },
    );
    return { upgraded: [...planned.keys()], blocked, pendingNative, createdPrimary: createPrimary };
  } finally {
    key.fill(0);
  }
}
