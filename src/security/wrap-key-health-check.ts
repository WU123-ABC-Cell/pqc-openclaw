// PQC step 2.3.7: wrap-key health check for `openclaw doctor`.
//
// Verifies that device_identities rows are decryptable:
// - all wrap columns reference keys that exist in the keyring
// - flags legacy rows (no wrap columns) so users can upgrade

import {
  openExistingOpenClawStateDatabaseReadOnly,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import { getOrCreateDefaultWrappingProvider } from "../infra/device-identity-store-keyring-default.js";
import type {
  HealthCheck,
  HealthCheckContext,
  HealthFinding,
} from "./health-checks.js";

const CHECK_ID = "core/doctor/wrap-key";

export interface WrapKeyHealthProbe {
  readonly totalIdentities: number;
  readonly wrappedIdentities: number;
  readonly legacyIdentities: number;
  readonly missingKeyIds: readonly string[];
}

export type WrapKeyHealthResult =
  | { readonly ok: true; readonly probe: WrapKeyHealthProbe; readonly findings: readonly HealthFinding[] }
  | { readonly ok: false; readonly error: string };

function finding(params: {
  severity: HealthFinding["severity"];
  message: string;
  path?: string;
  requirement?: string;
  fixHint?: string;
}): HealthFinding {
  return {
    checkId: CHECK_ID,
    source: "doctor",
    ...params,
  };
}

export async function runWrapKeyHealthCheck(
  options: OpenClawStateDatabaseOptions = {},
): Promise<WrapKeyHealthResult> {
  let database;
  try {
    database = await openExistingOpenClawStateDatabaseReadOnly(options);
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
  try {
    const rows = database.db.prepare(
      "SELECT device_id, private_key_wrap_key_id, mldsa_private_key_wrap_key_id FROM device_identities",
    ).all() as Array<{
      device_id: string;
      private_key_wrap_key_id: string | null;
      mldsa_private_key_wrap_key_id: string | null;
    }>;

    const totalIdentities = rows.length;
    const findings: HealthFinding[] = [];

    if (totalIdentities === 0) {
      return {
        ok: true,
        probe: { totalIdentities: 0, wrappedIdentities: 0, legacyIdentities: 0, missingKeyIds: [] },
        findings,
      };
    }

    let legacyCount = 0;
    let wrappedCount = 0;
    const referencedKeyIds = new Set<string>();
    for (const row of rows) {
      const hasWrap = row.private_key_wrap_key_id || row.mldsa_private_key_wrap_key_id;
      if (hasWrap) {
        wrappedCount++;
      } else {
        legacyCount++;
      }
      if (row.private_key_wrap_key_id) referencedKeyIds.add(row.private_key_wrap_key_id);
      if (row.mldsa_private_key_wrap_key_id) referencedKeyIds.add(row.mldsa_private_key_wrap_key_id);
    }

    const missingKeyIds: string[] = [];
    if (referencedKeyIds.size > 0) {
      const provider = getOrCreateDefaultWrappingProvider();
      for (const keyId of referencedKeyIds) {
        try {
          const key = provider.getKeyById(keyId);
          if (!key) missingKeyIds.push(keyId);
        } catch {
          missingKeyIds.push(keyId);
        }
      }
    }

    if (missingKeyIds.length > 0) {
      findings.push(finding({
        severity: "error",
        message: `${missingKeyIds.length} wrap key id(s) referenced by device identities are not in any keyring: ${missingKeyIds.join(", ")}`,
        path: "state.db:device_identities",
        requirement: "All device identity private keys must be decryptable",
        fixHint: "Restore the missing wrap keys from backup via `openclaw wrap-key import <backup-blob>`, or rotate to a new key with `openclaw wrap-key rotate`.",
      }));
    }

    if (legacyCount > 0) {
      findings.push(finding({
        severity: "info",
        message: `${legacyCount} of ${totalIdentities} device identity(ies) have no PQC wrap columns (legacy 2.1 or earlier plaintext).`,
        path: "state.db:device_identities",
        requirement: "Device identity private keys should be wrapped (PQC 2.3) for at-rest encryption",
        fixHint: "Run a key migration to upgrade legacy device identities to wrapped form.",
      }));
    }

    return {
      ok: true,
      probe: {
        totalIdentities,
        wrappedIdentities: wrappedCount,
        legacyIdentities: legacyCount,
        missingKeyIds,
      },
      findings,
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    if (database) {
      try {
        database.walMaintenance.close();
      } catch {
        // best-effort
      }
    }
  }
}

export const wrapKeyHealthCheck: HealthCheck = {
  id: CHECK_ID,
  kind: "core" as const,
  description: "Device identity wrap keys are present in the keyring and can decrypt stored secrets.",
  defaultEnabled: false as const,
  source: "doctor",
  async detect(_ctx: HealthCheckContext): Promise<readonly HealthFinding[]> {
    const result = runWrapKeyHealthCheck();
    if (!result.ok) {
      return [finding({
        severity: "error",
        message: `Could not inspect wrap-key state: ${result.error}`,
        requirement: "Wrap-key doctor requires readable state.db",
        fixHint: "Verify state.db is accessible before retrying.",
      })];
    }
    return result.findings;
  },
};
