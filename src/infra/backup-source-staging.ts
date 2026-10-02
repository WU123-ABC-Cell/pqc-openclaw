import type { Stats } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { sameFileIdentity } from "./fs-safe-advanced.js";
import { openLocalFileSafely } from "./fs-safe.js";

function unchangedSource(before: Stats, after: Stats): boolean {
  return (
    sameFileIdentity(before, after) &&
    before.size === after.size &&
    before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs &&
    before.mode === after.mode
  );
}

// Tar reopens paths after filtering. Stage from verified descriptors so a
// replaced candidate cannot turn an approved name into wrapping-key bytes.
export async function stageBackupSources(params: {
  sources: string[];
  directory: string;
  filter: (source: string, stat: Stats) => boolean;
  skipSource?: (source: string) => boolean;
  assertSafeRead: (source: string, stat: Stats) => Promise<void>;
}): Promise<{ sources: string[]; sourcePaths: Map<string, string> }> {
  await fs.mkdir(params.directory, { mode: 0o700 });
  const sourcePaths = new Map<string, string>();
  async function stage(source: string, destination: string): Promise<boolean> {
    if (params.skipSource?.(source)) {
      return false;
    }
    const stat = await fs.lstat(source);
    if (!params.filter(source, stat)) {
      return false;
    }
    if (stat.isDirectory()) {
      await fs.mkdir(destination, { mode: 0o700 });
      for (const child of await fs.readdir(source)) {
        await stage(path.join(source, child), path.join(destination, child));
      }
      await fs.chmod(destination, stat.mode & 0o777);
    } else if (stat.isSymbolicLink()) {
      await fs.symlink(await fs.readlink(source), destination);
    } else if (stat.isFile()) {
      const opened = await openLocalFileSafely({ filePath: source });
      try {
        if (!unchangedSource(stat, opened.stat)) {
          throw new Error(`Backup source changed before read: ${source}. Retry backup.`);
        }
        await params.assertSafeRead(source, opened.stat);
        const output = await fs.open(destination, "wx", 0o600);
        try {
          const buffer = Buffer.alloc(64 * 1024);
          let position = 0;
          while (position < opened.stat.size) {
            const length = Math.min(buffer.length, opened.stat.size - position);
            const { bytesRead } = await opened.handle.read(buffer, 0, length, position);
            if (bytesRead === 0) {
              throw new Error(`Backup source was truncated during read: ${source}. Retry backup.`);
            }
            await output.writeFile(buffer.subarray(0, bytesRead));
            position += bytesRead;
          }
          const after = await opened.handle.stat();
          if (!unchangedSource(opened.stat, after)) {
            throw new Error(`Backup source changed during read: ${source}. Retry backup.`);
          }
        } finally {
          await output.close();
        }
      } finally {
        await opened.handle.close();
      }
      await fs.chmod(destination, stat.mode & 0o777);
    } else {
      return false;
    }
    sourcePaths.set(path.resolve(destination), source);
    if (!stat.isSymbolicLink()) {
      await fs.utimes(destination, stat.atime, stat.mtime);
    }
    return true;
  }
  const sources: string[] = [];
  for (const [index, source] of params.sources.entries()) {
    const destination = path.join(params.directory, String(index));
    if (await stage(source, destination)) {
      sources.push(destination);
    }
  }
  return { sources, sourcePaths };
}
