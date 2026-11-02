import type { Stats } from "node:fs";
import syncFs from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { resolveWrappingKeyVaultPath } from "../security/wrap-key-file-install.js";
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

function within(file: string, directory: string): boolean {
  const candidate = normalized(file);
  const root = normalized(directory);
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

async function inspectVault(directory: string) {
  let stat: Stats;
  try {
    stat = await fs.lstat(directory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Wrapping-key vault must be a real directory: ${directory}`);
  }
  const names = (await fs.readdir(directory)).toSorted();
  const files = await Promise.all(
    names.map(async (name) => {
      const file = path.join(directory, name);
      const entry = await fs.lstat(file);
      if (!entry.isFile() || entry.isSymbolicLink()) {
        throw new Error(`Wrapping-key vault contains a non-file entry: ${file}`);
      }
      const identity = await inspect(file);
      if (!identity) {
        throw new Error(`Wrapping-key vault file disappeared: ${file}`);
      }
      return { file, identity };
    }),
  );
  return { stat, names, files };
}

// Inspect metadata only: backup must neither read nor create wrapping keys.
export async function createBackupWrappingKeyFilter(stateDir: string) {
  const vaultPath = resolveWrappingKeyVaultPath(stateDir);
  const vault = await inspectVault(vaultPath);
  const configured = process.env.OPENCLAW_WRAP_KEY_FILE;
  if (configured && !path.isAbsolute(configured)) {
    throw new Error("OPENCLAW_WRAP_KEY_FILE must be absolute for safe backup exclusion");
  }
  const files = [
    ...new Set([
      path.join(stateDir, "wrap-key.b64"),
      ...(configured ? [configured] : []),
      ...(vault?.files.map((entry) => entry.file) ?? []),
    ]),
  ];
  const snapshots = await Promise.all(
    files.map(async (file) => ({ file, lexical: normalized(file), identity: await inspect(file) })),
  );
  return {
    excludedFiles: snapshots.filter((entry) => entry.identity).map((entry) => entry.file),
    excludes(this: void, file: string, stat?: Stats): boolean {
      if (within(file, vaultPath)) {
        return true;
      }
      const lexical = normalized(file);
      if (stat?.isSymbolicLink()) {
        try {
          const target = normalized(syncFs.realpathSync.native(file));
          if (
            within(target, vaultPath) ||
            snapshots.some((entry) => target === entry.identity?.target)
          ) {
            return true;
          }
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
            throw error;
          }
        }
      }
      return snapshots.some(
        (entry) =>
          lexical === entry.lexical ||
          lexical === entry.identity?.target ||
          Boolean(stat?.isFile() && entry.identity && sameFileIdentity(stat, entry.identity.stat)),
      );
    },
    async assertSafeRead(this: void, file: string, stat: Stats): Promise<void> {
      if (within(file, vaultPath)) {
        throw new Error(`Backup source became a wrapping key: ${file}. Retry backup.`);
      }
      for (const entry of snapshots) {
        const current = await inspect(entry.file);
        if (
          normalized(file) === entry.lexical ||
          (entry.identity && sameFileIdentity(stat, entry.identity.stat)) ||
          (current && sameFileIdentity(stat, current.stat))
        ) {
          throw new Error(`Backup source became a wrapping key: ${file}. Retry backup.`);
        }
      }
    },
    async assertUnchanged(): Promise<void> {
      const currentVault = await inspectVault(vaultPath);
      if (
        Boolean(currentVault) !== Boolean(vault) ||
        (currentVault &&
          vault &&
          (!sameFileIdentity(currentVault.stat, vault.stat) ||
            currentVault.stat.mtimeMs !== vault.stat.mtimeMs ||
            currentVault.stat.ctimeMs !== vault.stat.ctimeMs ||
            currentVault.names.join("\0") !== vault.names.join("\0")))
      ) {
        throw new Error(`Wrapping-key vault changed during backup: ${vaultPath}. Retry backup.`);
      }
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
