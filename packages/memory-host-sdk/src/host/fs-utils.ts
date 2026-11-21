// Memory Host SDK helper module supports fs utils behavior.
import { configureFsSafeNative } from "@openclaw/fs-safe/config";
export { root } from "@openclaw/fs-safe/root";
export { isPathInside, isPathInsideWithRealpath } from "@openclaw/fs-safe/path";
export {
  assertNoSymlinkParents,
  readRegularFile,
  statRegularFile,
} from "@openclaw/fs-safe/advanced";
export { walkDirectory, type WalkDirectoryEntry } from "@openclaw/fs-safe/walk";

// Windows device identity uses the shared native ACL backend.
// Preserve the host's Windows mode and any explicit environment override.
if (
  process.platform !== "win32" &&
  !Object.keys(process.env).some((key) =>
    /^(?:OPENCLAW_)?FS_SAFE_(?:NATIVE|PYTHON)_MODE$/u.test(key),
  )
) {
  configureFsSafeNative({ mode: "off" });
}

/** True for missing-file errors emitted by Node or fs-safe. */
export function isFileMissingError(
  err: unknown,
): err is NodeJS.ErrnoException & { code: "ENOENT" | "ENOTDIR" | "not-found" } {
  return Boolean(
    err &&
    typeof err === "object" &&
    "code" in err &&
    ((err as Partial<NodeJS.ErrnoException>).code === "ENOENT" ||
      (err as Partial<NodeJS.ErrnoException>).code === "ENOTDIR" ||
      (err as { code?: unknown }).code === "not-found"),
  );
}
