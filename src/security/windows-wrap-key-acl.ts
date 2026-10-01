import { lstatSync } from "node:fs";
import { dirname } from "node:path";
import { readOwnerAndDacl, type OwnerAndDaclResult } from "@openclaw/fs-safe/permissions";

type WindowsAclFacts = Extract<OwnerAndDaclResult, { status: "supported" }>;

const SYSTEM_SID = "s-1-5-18";
const ADMINISTRATORS_SID = "s-1-5-32-544";
const CREATOR_OWNER_SID = "s-1-3-0";
const TRUSTED_INSTALLER_SID = "s-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const ANCESTOR_MUTATION_RIGHTS =
  0x00000040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000;

/** A wrap key must never inherit access for another local account or group. */
export function isPrivateWindowsWrapKeyAcl(
  facts: WindowsAclFacts,
  kind: "file" | "directory" = "directory",
): boolean {
  const trusted = new Set([facts.currentUserSid.toLowerCase(), SYSTEM_SID, ADMINISTRATORS_SID]);
  return (
    facts.isLocal &&
    facts.daclPresent &&
    facts.complete &&
    trusted.has(facts.ownerSid.toLowerCase()) &&
    facts.aces.every(
      (ace) =>
        ace.aceType !== "allow" ||
        trusted.has(ace.sid.toLowerCase()) ||
        (ace.flags.inheritOnly && (kind === "file" || ace.sid.toLowerCase() === CREATOR_OWNER_SID)),
    )
  );
}

/** An account able to replace an ancestor can redirect a path after inspection. */
export function isStableWindowsWrapKeyAncestorAcl(facts: WindowsAclFacts): boolean {
  const trusted = new Set([
    facts.currentUserSid.toLowerCase(),
    SYSTEM_SID,
    ADMINISTRATORS_SID,
    TRUSTED_INSTALLER_SID,
  ]);
  return (
    facts.isLocal &&
    facts.daclPresent &&
    facts.complete &&
    trusted.has(facts.ownerSid.toLowerCase()) &&
    facts.aces.every(
      (ace) =>
        ace.aceType !== "allow" ||
        ace.flags.inheritOnly ||
        trusted.has(ace.sid.toLowerCase()) ||
        (ace.mask & ANCESTOR_MUTATION_RIGHTS) === 0,
    )
  );
}

function assertStableWindowsAncestors(directoryPath: string): void {
  let ancestor = dirname(directoryPath);
  for (;;) {
    const stat = lstatSync(ancestor);
    const facts = readOwnerAndDacl(ancestor);
    if (
      stat.isSymbolicLink() ||
      !stat.isDirectory() ||
      facts.status !== "supported" ||
      !isStableWindowsWrapKeyAncestorAcl(facts)
    ) {
      throw new Error(`Refusing wrapping-key path under unsafe Windows ancestor: ${ancestor}`);
    }
    const parent = dirname(ancestor);
    if (parent === ancestor) {
      return;
    }
    ancestor = parent;
  }
}

function assertPrivateWindowsAcl(targetPath: string, kind: "file" | "directory"): void {
  const stat = lstatSync(targetPath);
  if (stat.isSymbolicLink() || (kind === "file" ? !stat.isFile() : !stat.isDirectory())) {
    throw new Error(`Refusing unsafe wrapping-key ${kind} path: ${targetPath}`);
  }
  const facts = readOwnerAndDacl(targetPath);
  if (facts.status !== "supported" || !isPrivateWindowsWrapKeyAcl(facts, kind)) {
    throw new Error(
      `Refusing wrapping-key ${kind} with unverified or unsafe Windows ACL: ${targetPath}`,
    );
  }
}

/** Check the parent before a new key is created, so inherited ACLs are private. */
export function assertPrivateWindowsWrapKeyDirectory(directoryPath: string): void {
  if (process.platform === "win32") {
    assertStableWindowsAncestors(directoryPath);
    assertPrivateWindowsAcl(directoryPath, "directory");
  }
}

/** Recheck even when the key bytes are cached: permissions may change later. */
export function assertPrivateWindowsWrapKeyFile(keyPath: string): void {
  if (process.platform === "win32") {
    assertPrivateWindowsWrapKeyDirectory(dirname(keyPath));
    assertPrivateWindowsAcl(keyPath, "file");
  }
}
