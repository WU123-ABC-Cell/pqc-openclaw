import { lstatSync } from "node:fs";
import { dirname } from "node:path";
import { readOwnerAndDacl, type OwnerAndDaclResult } from "../infra/permissions.js";
import { pqcLog, PQC_EVENT } from "../logging/pqc-log.js";

type WindowsAclFacts = Extract<OwnerAndDaclResult, { status: "supported" }>;

const SYSTEM_SID = "s-1-5-18";
const ADMINISTRATORS_SID = "s-1-5-32-544";
const CREATOR_OWNER_SID = "s-1-3-0";
const TRUSTED_INSTALLER_SID = "s-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const ANCESTOR_MUTATION_RIGHTS =
  0x00000040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000;

type WindowsAclTarget = "file" | "directory" | "ancestor";
type WindowsAclRejection =
  | "descriptor-unavailable"
  | "non-local-path"
  | "missing-dacl"
  | "incomplete-dacl"
  | "untrusted-owner"
  | "untrusted-allow-ace"
  | "unsafe-path-type";

function getWindowsAclRejection(
  facts: OwnerAndDaclResult,
  target: WindowsAclTarget,
): WindowsAclRejection | undefined {
  if (facts.status !== "supported") {
    return "descriptor-unavailable";
  }
  if (!facts.isLocal) {
    return "non-local-path";
  }
  if (!facts.daclPresent) {
    return "missing-dacl";
  }
  if (!facts.complete) {
    return "incomplete-dacl";
  }
  const trusted = new Set([facts.currentUserSid.toLowerCase(), SYSTEM_SID, ADMINISTRATORS_SID]);
  if (target === "ancestor") {
    trusted.add(TRUSTED_INSTALLER_SID);
  }
  if (!trusted.has(facts.ownerSid.toLowerCase())) {
    return "untrusted-owner";
  }
  const hasUntrustedAllowAce = facts.aces.some((ace) => {
    if (ace.aceType !== "allow") {
      return false;
    }
    const sid = ace.sid.toLowerCase();
    if (trusted.has(sid)) {
      return false;
    }
    if (target === "ancestor") {
      return !ace.flags.inheritOnly && (ace.mask & ANCESTOR_MUTATION_RIGHTS) !== 0;
    }
    return !ace.flags.inheritOnly || (target === "directory" && sid !== CREATOR_OWNER_SID);
  });
  return hasUntrustedAllowAce ? "untrusted-allow-ace" : undefined;
}

/** A wrap key must never inherit access for another local account or group. */
export function isPrivateWindowsWrapKeyAcl(
  facts: WindowsAclFacts,
  kind: "file" | "directory" = "directory",
): boolean {
  return getWindowsAclRejection(facts, kind) === undefined;
}

/** An account able to replace an ancestor can redirect a path after inspection. */
export function isStableWindowsWrapKeyAncestorAcl(facts: WindowsAclFacts): boolean {
  return getWindowsAclRejection(facts, "ancestor") === undefined;
}

function logWindowsAclRejection(target: WindowsAclTarget, reason: WindowsAclRejection): void {
  try {
    pqcLog.warn(PQC_EVENT.WrapKey, {
      status: "refused",
      detail: `windows-acl ${target}: ${reason}`,
    });
  } catch {
    // Keep the existing refusal if the log transport is unavailable.
  }
}

function assertStableWindowsAncestors(directoryPath: string): void {
  let ancestor = dirname(directoryPath);
  for (;;) {
    const stat = lstatSync(ancestor);
    const facts = readOwnerAndDacl(ancestor);
    const reason =
      stat.isSymbolicLink() || !stat.isDirectory()
        ? "unsafe-path-type"
        : getWindowsAclRejection(facts, "ancestor");
    if (reason) {
      logWindowsAclRejection("ancestor", reason);
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
  const reason = getWindowsAclRejection(readOwnerAndDacl(targetPath), kind);
  if (reason) {
    logWindowsAclRejection(kind, reason);
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
