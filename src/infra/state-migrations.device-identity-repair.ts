// Doctor-only detection and atomic wrapping upgrade of canonical identity populations.
import fs from "node:fs";
import path from "node:path";
import {
  DeviceIdentityStorageError,
  listDeviceIdentityWrappingUpgrades,
  readStoredDeviceIdentityReadOnly,
  upgradeDeviceIdentityPopulationWrapped,
} from "./device-identity-store.js";
import { resolveDeviceIdentityWrappingOptions } from "./device-identity.js";
import { formatErrorMessage } from "./errors.js";
import type { LegacyDeviceIdentityDetection } from "./state-migrations.device-identity.types.js";
import type { MigrationMessages } from "./state-migrations.types.js";

const LEGACY_IDENTITY_RELATIVE_PATH = path.join("identity", "device.json");
const DOCTOR_CLAIM_SUFFIX = ".doctor-importing";
const NATIVE_CLAIM_SUFFIX = ".native-importing";
const IDENTITY_KEY = "primary";

function pathMayExist(filePath: string): boolean {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

/** Detect the exact retired paths and invalid canonical row only with Doctor authority. */
export function detectLegacyDeviceIdentity(params: {
  stateDir: string;
  env?: NodeJS.ProcessEnv;
  doctorOnlyStateMigrations?: boolean;
}): LegacyDeviceIdentityDetection {
  const sourcePath = path.join(params.stateDir, LEGACY_IDENTITY_RELATIVE_PATH);
  const claimPath = `${sourcePath}${DOCTOR_CLAIM_SUFFIX}`;
  const nativeClaimPath = `${sourcePath}${NATIVE_CLAIM_SUFFIX}`;
  const doctorAuthorized = params.doctorOnlyStateMigrations === true;
  let hasInvalidCanonical = false;
  if (doctorAuthorized) {
    try {
      const options = resolveDeviceIdentityWrappingOptions(
        {
          env: { ...(params.env ?? process.env), OPENCLAW_STATE_DIR: params.stateDir },
          identityKey: IDENTITY_KEY,
        },
        false,
      );
      readStoredDeviceIdentityReadOnly(options);
      hasInvalidCanonical = listDeviceIdentityWrappingUpgrades(options).length > 0;
    } catch {
      hasInvalidCanonical = true;
    }
  }
  return {
    sourcePath,
    claimPath,
    nativeClaimPath,
    hasLegacy:
      doctorAuthorized &&
      (pathMayExist(claimPath) || pathMayExist(nativeClaimPath) || pathMayExist(sourcePath)),
    hasInvalidCanonical,
  };
}

export function hasLegacyDeviceIdentityPath(detected: LegacyDeviceIdentityDetection): boolean {
  return (
    pathMayExist(detected.claimPath) ||
    pathMayExist(detected.nativeClaimPath) ||
    pathMayExist(detected.sourcePath)
  );
}

/** Upgrade only after the caller acquires Doctor's exclusive state lock. Never replace blocked rows. */
export function repairInvalidCanonicalIdentity(env: NodeJS.ProcessEnv): MigrationMessages {
  const changes: string[] = [];
  const warnings: string[] = [];
  try {
    const options = resolveDeviceIdentityWrappingOptions({ env, identityKey: IDENTITY_KEY }, true);
    const wrappingKeyProvider = options.wrappingKeyProvider;
    if (!wrappingKeyProvider) {
      throw new DeviceIdentityStorageError(
        "A wrapping key provider is required before Doctor can replace a device identity.",
      );
    }
    const result = upgradeDeviceIdentityPopulationWrapped(options);
    changes.push(
      ...result.upgraded.map(
        (identityKey) =>
          `Upgraded authenticated wrapping for device identity "${identityKey}" in SQLite.`,
      ),
    );
    warnings.push(
      ...result.blocked.map(
        (row) =>
          `Could not upgrade wrapping for device identity "${row.identityKey}"; the entire identity population was preserved. Restore its key or backup before retrying.`,
      ),
    );
    warnings.push(
      ...result.pendingNative.map(
        (identityKey) =>
          `Device identity "${identityKey}" was preserved and still requires native Apple verification.`,
      ),
    );
    return { changes, warnings };
  } catch (error) {
    return {
      changes,
      warnings: [
        ...warnings,
        `Failed repairing invalid SQLite device identity: ${formatErrorMessage(error)}`,
      ],
    };
  }
}
