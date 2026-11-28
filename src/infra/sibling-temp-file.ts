import "./fs-safe-defaults.js";
import {
  writeSiblingTempFile as writeSiblingTempFileBase,
  type WriteSiblingTempFileOptions,
} from "@openclaw/fs-safe/advanced";

// Take ownership of the staging workspace before a producer can leave partial output.
export function writeSiblingTempFile<T>(
  options: Omit<WriteSiblingTempFileOptions<T>, "producerIsolation">,
) {
  return writeSiblingTempFileBase({ ...options, producerIsolation: "private-directory" });
}
