import type { Stats } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { sameFileIdentity } from "./fs-safe-advanced.js";

function normalized(file: string): string {
  const resolved = path.resolve(file);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

async function inspect(file: string): Promise<{ target: string; stat: Stats } | undefined> {
  try {
    const target = await fs.realpath(file);
    const stat = await fs.stat(target);
    if (!stat.isFile()) {
      throw new Error(`Wrapping key must be a regular file: ${file}`);
    }
    return { target: normalized(target), stat };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

// Inspect metadata only: backup must neither read nor create wrapping keys.
export async function createBackupWrappingKeyFilter(stateDir: string) {
  const configured = process.env.OPENCLAW_WRAP_KEY_FILE;
  if (configured && !path.isAbsolute(configured)) {
    throw new Error("OPENCLAW_WRAP_KEY_FILE must be absolute for safe backup exclusion");
  }
  const files = [
    ...new Set([path.join(stateDir, "wrap-key.b64"), ...(configured ? [configured] : [])]),
  ];
  const snapshots = await Promise.all(
    files.map(async (file) => ({ file, lexical: normalized(file), identity: await inspect(file) })),
  );
  return {
    excludedFiles: snapshots.filter((entry) => entry.identity).map((entry) => entry.file),
    excludes(file: string, stat?: Stats): boolean {
      const lexical = normalized(file);
      return snapshots.some(
        (entry) =>
          lexical === entry.lexical ||
          lexical === entry.identity?.target ||
          Boolean(stat?.isFile() && entry.identity && sameFileIdentity(stat, entry.identity.stat)),
      );
    },
    async assertUnchanged(): Promise<void> {
      for (const entry of snapshots) {
        const current = await inspect(entry.file);
        const previous = entry.identity;
        if (
          Boolean(current) !== Boolean(previous) ||
          (current &&
            previous &&
            (current.target !== previous.target ||
              !sameFileIdentity(current.stat, previous.stat) ||
              current.stat.size !== previous.stat.size ||
              current.stat.mtimeMs !== previous.stat.mtimeMs ||
              current.stat.ctimeMs !== previous.stat.ctimeMs))
        ) {
          throw new Error(`Wrapping key changed during backup: ${entry.file}. Retry backup.`);
        }
      }
    },
  };
}
