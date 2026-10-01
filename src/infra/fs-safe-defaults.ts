// Applies OpenClaw's default fs-safe runtime configuration.
import { configureFsSafeNative } from "@openclaw/fs-safe/config";

// Windows wrapping-key ACL inspection requires the bundled native helper.
// Other platforms retain the non-native default. Explicit mode overrides remain
// authoritative; file-keyring ACL inspection fails closed when unavailable.
const hasModeOverride = Object.keys(process.env).some((key) =>
  /^(?:OPENCLAW_)?FS_SAFE_(?:NATIVE|PYTHON)_MODE$/u.test(
    process.platform === "win32" ? key.toUpperCase() : key,
  ),
);

if (!hasModeOverride) {
  configureFsSafeNative({ mode: process.platform === "win32" ? "auto" : "off" });
}
