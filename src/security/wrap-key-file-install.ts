import { timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { encodeBase64UrlKey, FileKeyring, generateWrappingKey } from "./keyring-provider.js";
import {
  assertPrivateWindowsWrapKeyDirectory,
  assertPrivateWindowsWrapKeyFile,
} from "./windows-wrap-key-acl.js";

const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/u;

function assertKeyId(keyId: string): void {
  if (!KEY_ID.test(keyId)) {
    throw new Error("Wrapping-key ID must contain 1-64 ASCII letters, digits, _ or -.");
  }
}

/** Separate from state archives. Each file is an immutable key-ID slot. */
export function resolveWrappingKeyVaultPath(stateDir: string): string {
  const resolved = path.resolve(stateDir);
  const canonical = fs.existsSync(resolved) ? fs.realpathSync.native(resolved) : resolved;
  return path.join(path.dirname(canonical), `${path.basename(canonical)}.wrap-keys`);
}

function assertPrivateVault(vaultPath: string): void {
  const vault = fs.lstatSync(vaultPath);
  if (
    vault.isSymbolicLink() ||
    !vault.isDirectory() ||
    (process.platform !== "win32" && (vault.mode & 0o077) !== 0)
  ) {
    throw new Error("Wrapping-key vault must be a private real directory under a stable parent.");
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid !== undefined && vault.uid !== uid) {
    throw new Error("Wrapping-key vault must belong to the current user.");
  }
  if (process.platform !== "win32") {
    let ancestor = path.dirname(vaultPath);
    for (;;) {
      const stat = fs.lstatSync(ancestor);
      const trustedOwner = uid === undefined || stat.uid === uid || stat.uid === 0;
      const privateDirectory = (stat.mode & 0o022) === 0;
      const rootStickyDirectory = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
      if (
        stat.isSymbolicLink() ||
        !stat.isDirectory() ||
        !trustedOwner ||
        (!privateDirectory && !rootStickyDirectory)
      ) {
        throw new Error("Wrapping-key vault has a replaceable or untrusted ancestor.");
      }
      const parent = path.dirname(ancestor);
      if (parent === ancestor) {
        break;
      }
      ancestor = parent;
    }
  }
  assertPrivateWindowsWrapKeyDirectory(vaultPath);
}

/** Create a new key without overwriting any existing slot or touching identity state. */
export function prepareFileWrappingKey(
  stateDir: string,
  keyId: string,
): { keyId: string; keyPath: string } {
  assertKeyId(keyId);
  const canonicalStateDir = fs.realpathSync.native(stateDir);
  const stateStat = fs.lstatSync(canonicalStateDir);
  if (!stateStat.isDirectory() || stateStat.isSymbolicLink()) {
    throw new Error("Wrapping-key preparation requires an existing state directory.");
  }
  const vaultPath = resolveWrappingKeyVaultPath(canonicalStateDir);
  try {
    fs.mkdirSync(vaultPath, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      throw error;
    }
  }
  assertPrivateVault(vaultPath);
  const keyPath = path.join(vaultPath, `${keyId}.b64`);
  const key = generateWrappingKey();
  let fd: number | undefined;
  try {
    fd = fs.openSync(keyPath, "wx", 0o600);
    fs.writeSync(fd, encodeBase64UrlKey(key));
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    const verified = openPreparedFileWrappingKey(canonicalStateDir, keyId);
    try {
      const reopened = verified.getActiveKey();
      if (reopened.keyId !== keyId || !timingSafeEqual(reopened.key, key)) {
        throw new Error("New wrapping-key file did not verify after installation.");
      }
    } finally {
      verified.release();
    }
    if (process.platform !== "win32") {
      const directoryFd = fs.openSync(vaultPath, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
      try {
        fs.fsyncSync(directoryFd);
      } finally {
        fs.closeSync(directoryFd);
      }
    }
    return { keyId, keyPath };
  } catch (error) {
    // A failed publication can leave a partial slot. Never overwrite or silently
    // remove it: recovery must inspect the exact path before any retry.
    throw new Error(`Wrapping-key preparation failed; inspect ${keyPath} before retrying.`, {
      cause: error,
    });
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
    key.fill(0);
  }
}

/** Revalidate a prepared slot from disk; callers own and must release the provider. */
export function openPreparedFileWrappingKey(stateDir: string, keyId: string): FileKeyring {
  assertKeyId(keyId);
  const vaultPath = resolveWrappingKeyVaultPath(fs.realpathSync.native(stateDir));
  assertPrivateVault(vaultPath);
  const keyPath = path.join(vaultPath, `${keyId}.b64`);
  const stat = fs.lstatSync(keyPath);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    (uid !== undefined && stat.uid !== uid) ||
    (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
  ) {
    throw new Error("Prepared wrapping-key slot has unsafe type, links, owner, or permissions.");
  }
  assertPrivateWindowsWrapKeyFile(keyPath);
  return new FileKeyring(keyPath, keyId);
}
