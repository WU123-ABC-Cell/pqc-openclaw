import { resolveDeviceIdentityWrappingOptions } from "../infra/device-identity.js";
import { defaultRuntime } from "../runtime.js";
import { wrapKeyStatusCommand, type WrapKeyStatus } from "../security/wrap-key-cli.js";

export async function runWrapKeyStatus(opts: {
  identityKey: string;
  json: boolean;
}): Promise<boolean> {
  const identityKeys = [opts.identityKey];
  try {
    const options = resolveDeviceIdentityWrappingOptions({ env: process.env }, false);
    const provider = options.wrappingKeyProvider;
    let health: WrapKeyStatus;
    try {
      health = await wrapKeyStatusCommand({ options, identityKeys });
    } finally {
      // Release one-shot provider buffers before reporting or exiting, including
      // after a failed read; a cleanup failure must not publish a healthy result.
      if (provider && "release" in provider && typeof provider.release === "function") {
        provider.release();
      }
    }
    // Provider/store error text and helper-only cost/count hints are not a
    // public diagnostic contract. Emit metadata, never key material or raw errors.
    const report = {
      ok: health.ok,
      identityKeys,
      provider: health.provider,
      activeKeyId: health.activeKeyId,
      rows: health.rows.map(({ identityKey, deviceId, state, wrapKeyId }) => ({
        identityKey,
        deviceId,
        state,
        wrapKeyId,
      })),
    };
    if (opts.json) {
      defaultRuntime.writeJson(report);
    } else {
      defaultRuntime.log(`Wrapping-key status: ${report.ok ? "healthy" : "unavailable"}`);
      defaultRuntime.log(
        `Provider: ${report.provider}; active key ID: ${report.activeKeyId || "none"}`,
      );
      defaultRuntime.log(`Checked identity: ${opts.identityKey} (not an all-identities scan)`);
      for (const row of report.rows) {
        defaultRuntime.log(
          `${row.identityKey}: ${row.state}; stored key ID: ${row.wrapKeyId ?? "none"}`,
        );
      }
      if (report.rows.some((row) => row.state === "plaintext")) {
        defaultRuntime.log(
          "Warning: the checked identity is usable but its private key is not wrapped.",
        );
      }
    }
    return report.ok;
  } catch {
    const report = { ok: false, identityKeys, error: "wrapping-key-status-unavailable" };
    if (opts.json) {
      defaultRuntime.writeJson(report);
    } else {
      defaultRuntime.error(
        "Wrapping-key status unavailable. Check provider configuration and key permissions.",
      );
    }
    return false;
  }
}
