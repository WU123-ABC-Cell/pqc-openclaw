import { resolveStateDir } from "../config/paths.js";
import { defaultRuntime } from "../runtime.js";
import { prepareFileWrappingKey } from "../security/wrap-key-file-install.js";

/** Install a new independent key slot; never change the active runtime key. */
export function runWrapKeyPrepare(opts: { keyId: string; json: boolean }): boolean {
  try {
    const prepared = prepareFileWrappingKey(resolveStateDir(process.env), opts.keyId);
    if (opts.json) {
      defaultRuntime.writeJson({ ok: true, ...prepared, active: false });
    } else {
      defaultRuntime.log(`Prepared wrapping key ${prepared.keyId}: ${prepared.keyPath}`);
      defaultRuntime.log("The active key is unchanged. Retain old keys for existing backups.");
    }
    return true;
  } catch {
    if (opts.json) {
      defaultRuntime.writeJson({ ok: false, error: "wrapping-key-prepare-failed" });
    } else {
      defaultRuntime.error(
        "Wrapping-key preparation failed. Check the selected state directory, vault permissions, and whether the key ID already exists.",
      );
    }
    return false;
  }
}
