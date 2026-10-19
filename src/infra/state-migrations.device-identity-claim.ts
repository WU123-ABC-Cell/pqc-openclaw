import type { Root } from "@openclaw/fs-safe";
import { publishFileNoClobber } from "./directory-durability.js";
import {
  legacyMigrationSourceSnapshotsMatch,
  readLegacyMigrationSourceSnapshot,
  resolveLegacyMigrationRelativePath,
  type LegacyMigrationSourceSnapshot,
} from "./state-migrations.source-snapshot.js";

export const MAX_LEGACY_IDENTITY_BYTES = 128 * 1024;

type LegacyPathParams = { stateRoot: Root; stateDir: string; sourcePath: string };

function relativePath(stateDir: string, filePath: string): string {
  return resolveLegacyMigrationRelativePath(stateDir, filePath, "device identity", false);
}

async function readBytes(params: LegacyPathParams): Promise<LegacyMigrationSourceSnapshot> {
  return await readLegacyMigrationSourceSnapshot({
    ...params,
    maxBytes: MAX_LEGACY_IDENTITY_BYTES,
    label: "device identity",
  });
}

/** Publish one complete inode at a new name, then retire its old name. */
export async function moveLegacyIdentityPathWithoutOverwrite(
  params: LegacyPathParams & {
    targetPath: string;
    snapshot: LegacyMigrationSourceSnapshot;
  },
): Promise<LegacyMigrationSourceSnapshot> {
  if (!legacyMigrationSourceSnapshotsMatch(params.snapshot, await readBytes(params))) {
    throw new Error("legacy device identity source changed before publication");
  }
  await publishFileNoClobber(
    await params.stateRoot.resolve(relativePath(params.stateDir, params.sourcePath)),
    await params.stateRoot.resolve(relativePath(params.stateDir, params.targetPath)),
    { strategy: "link-required", moveSource: true, durability: "degrade" },
  );
  const opened = await params.stateRoot.open(relativePath(params.stateDir, params.targetPath));
  try {
    await opened.handle.chmod(0o600);
    await opened.handle.sync();
  } finally {
    await opened.handle.close();
  }
  const target = await readBytes({ ...params, sourcePath: params.targetPath });
  if (!legacyMigrationSourceSnapshotsMatch(params.snapshot, target)) {
    throw new Error("legacy device identity changed during publication");
  }
  return target;
}

/** A completed duplicate copy can be discarded; a conflicting claim is retained. */
export async function restoreLegacyIdentityClaim(
  params: LegacyPathParams & { claimPath: string },
): Promise<string | null> {
  try {
    if (!(await params.stateRoot.exists(relativePath(params.stateDir, params.claimPath)))) {
      return null;
    }
    if (await params.stateRoot.exists(relativePath(params.stateDir, params.sourcePath))) {
      const sourceStat = await params.stateRoot.stat(
        relativePath(params.stateDir, params.sourcePath),
      );
      const claimStat = await params.stateRoot.stat(
        relativePath(params.stateDir, params.claimPath),
      );
      if (
        sourceStat.isFile &&
        claimStat.isFile &&
        sourceStat.dev === claimStat.dev &&
        sourceStat.ino === claimStat.ino &&
        sourceStat.nlink === 2 &&
        claimStat.nlink === 2
      ) {
        await params.stateRoot.remove(relativePath(params.stateDir, params.claimPath));
        return null;
      }
    }
    const claim = await readBytes({ ...params, sourcePath: params.claimPath });
    if (await params.stateRoot.exists(relativePath(params.stateDir, params.sourcePath))) {
      const source = await readBytes(params);
      if (source.sha256 !== claim.sha256 || source.size !== claim.size) {
        return `source path already exists: ${params.sourcePath}`;
      }
      if (
        !legacyMigrationSourceSnapshotsMatch(source, await readBytes(params)) ||
        !legacyMigrationSourceSnapshotsMatch(
          claim,
          await readBytes({ ...params, sourcePath: params.claimPath }),
        )
      ) {
        throw new Error("source or claim changed before duplicate cleanup");
      }
      await params.stateRoot.remove(relativePath(params.stateDir, params.claimPath));
      return null;
    }
    await moveLegacyIdentityPathWithoutOverwrite({
      ...params,
      sourcePath: params.claimPath,
      targetPath: params.sourcePath,
      snapshot: claim,
    });
    return null;
  } catch (error) {
    return String(error);
  }
}
