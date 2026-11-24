import { realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PQC_EVENT, setPqcEmit, type PqcEmit } from "../logging/pqc-log.js";
import { withTempDir } from "../test-utils/temp-dir.js";
import {
  assertPrivateWindowsWrapKeyDirectory,
  assertPrivateWindowsWrapKeyFile,
  isPrivateWindowsWrapKeyAcl,
  isStableWindowsWrapKeyAncestorAcl,
} from "./windows-wrap-key-acl.js";

const readOwnerAndDacl = vi.hoisted(() =>
  vi.fn<typeof import("../infra/permissions.js").readOwnerAndDacl>(),
);
vi.mock("../infra/permissions.js", () => ({ readOwnerAndDacl }));

type Facts = Parameters<typeof isPrivateWindowsWrapKeyAcl>[0];

const USER = "s-1-5-21-1-2-3-1001";
const OTHER_USER = "s-1-5-21-1-2-3-1002";

function facts(overrides: Partial<Facts> = {}): Facts {
  return {
    status: "supported",
    ownerSid: USER,
    currentUserSid: USER,
    daclPresent: true,
    isLocal: true,
    complete: true,
    unsupportedAceTypes: [],
    aces: [USER, "s-1-5-18", "s-1-5-32-544"].map((sid) => ({
      sid,
      mask: 0x1f01ff,
      aceType: "allow" as const,
      flags: {
        raw: 0,
        objectInherit: false,
        containerInherit: false,
        noPropagateInherit: false,
        inheritOnly: false,
        inherited: false,
        successfulAccess: false,
        failedAccess: false,
      },
    })),
    ...overrides,
  };
}

describe("Windows wrap-key ACL policy", () => {
  it("allows CREATOR OWNER inheritance but rejects inheritance to another account", () => {
    const base = facts();
    const ace = {
      ...base.aces[0]!,
      sid: "s-1-3-0",
      flags: { ...base.aces[0]!.flags, inheritOnly: true },
    };
    expect(isPrivateWindowsWrapKeyAcl(facts({ aces: [...base.aces, ace] }))).toBe(true);
    expect(
      isPrivateWindowsWrapKeyAcl(facts({ aces: [...base.aces, { ...ace, sid: OTHER_USER }] })),
    ).toBe(false);
    expect(isPrivateWindowsWrapKeyAcl(facts({ aces: [ace] }), "file")).toBe(true);
  });

  it("allows ancestor read access but rejects rights that can replace the key path", () => {
    const base = facts();
    const ace = { ...base.aces[0]!, sid: OTHER_USER, mask: 0x1200a9 };
    expect(isStableWindowsWrapKeyAncestorAcl(facts({ aces: [...base.aces, ace] }))).toBe(true);
    for (const mask of [0x40, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000]) {
      expect(
        isStableWindowsWrapKeyAncestorAcl(facts({ aces: [...base.aces, { ...ace, mask }] })),
      ).toBe(false);
    }
    expect(isStableWindowsWrapKeyAncestorAcl(facts({ ownerSid: OTHER_USER }))).toBe(false);
  });
  it("accepts only the current user, SYSTEM, and Administrators", () => {
    expect(isPrivateWindowsWrapKeyAcl(facts())).toBe(true);
  });

  it("rejects another user or group even when the ACE is inherited", () => {
    const privateFacts = facts();
    const exposed = facts({
      aces: [
        ...privateFacts.aces,
        {
          ...privateFacts.aces[0]!,
          sid: OTHER_USER,
          flags: { ...privateFacts.aces[0]!.flags, inherited: true },
        },
      ],
    });
    expect(isPrivateWindowsWrapKeyAcl(exposed)).toBe(false);
  });

  it.each([
    { name: "foreign owner", overrides: { ownerSid: OTHER_USER } },
    { name: "remote filesystem", overrides: { isLocal: false } },
    { name: "null DACL", overrides: { daclPresent: false } },
    { name: "incomplete descriptor", overrides: { complete: false } },
  ])("rejects $name", ({ overrides }) => {
    expect(isPrivateWindowsWrapKeyAcl(facts(overrides))).toBe(false);
  });
});

describe("Windows wrap-key ACL diagnostics", () => {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const emit = vi.fn<PqcEmit>();

  beforeEach(() => {
    Object.defineProperty(process, "platform", { ...platform, value: "win32" });
    readOwnerAndDacl.mockReset();
    emit.mockReset();
    setPqcEmit(emit);
  });

  afterEach(() => {
    Object.defineProperty(process, "platform", platform);
    setPqcEmit(null);
  });

  it.each([
    {
      reason: "descriptor-unavailable",
      acl: { status: "unsupported-platform", platform: "linux" } as const,
    },
    { reason: "non-local-path", acl: facts({ isLocal: false }) },
    { reason: "missing-dacl", acl: facts({ daclPresent: false }) },
    { reason: "incomplete-dacl", acl: facts({ complete: false, unsupportedAceTypes: [5] }) },
    { reason: "untrusted-owner", acl: facts({ ownerSid: OTHER_USER }) },
    {
      reason: "untrusted-allow-ace",
      acl: facts({ aces: [{ ...facts().aces[0]!, sid: OTHER_USER }] }),
    },
  ])("records only the fixed directory reason $reason", async ({ reason, acl }) => {
    await withTempDir("wrap-key-acl-", async (temp) => {
      const dir = realpathSync(temp);
      readOwnerAndDacl.mockImplementation((target) => (target === dir ? acl : facts()));

      expect(() => assertPrivateWindowsWrapKeyDirectory(dir)).toThrow(
        "Refusing wrapping-key directory with unverified or unsafe Windows ACL: " + dir,
      );
      expect(emit.mock.calls).toEqual([
        [
          "warn",
          PQC_EVENT.WrapKey,
          { status: "refused", detail: "windows-acl directory: " + reason },
        ],
      ]);
    });
  });

  it("distinguishes inherited path risk from a key file ACL denial", async () => {
    await withTempDir("wrap-key-acl-targets-", async (temp) => {
      const dir = realpathSync(temp);
      const keyPath = join(dir, "wrap-key.b64");
      writeFileSync(keyPath, "");
      const base = facts();
      const extra = { ...base.aces[0]!, sid: OTHER_USER };
      readOwnerAndDacl.mockImplementation((target) =>
        target === keyPath ? facts({ aces: [...base.aces, extra] }) : base,
      );

      expect(() => assertPrivateWindowsWrapKeyFile(keyPath)).toThrow("unsafe Windows ACL");
      expect(emit.mock.calls).toEqual([
        [
          "warn",
          PQC_EVENT.WrapKey,
          { status: "refused", detail: "windows-acl file: untrusted-allow-ace" },
        ],
      ]);

      emit.mockClear();
      readOwnerAndDacl.mockImplementation((target) =>
        target === dir ? facts({ aces: [...base.aces, extra] }) : base,
      );

      expect(() => assertPrivateWindowsWrapKeyDirectory(join(dir, "state"))).toThrow(
        "unsafe Windows ancestor",
      );
      expect(emit.mock.calls).toEqual([
        [
          "warn",
          PQC_EVENT.WrapKey,
          { status: "refused", detail: "windows-acl ancestor: untrusted-allow-ace" },
        ],
      ]);
    });
  });

  it("keeps the ACL refusal when diagnostic logging fails", async () => {
    await withTempDir("wrap-key-acl-log-", async (temp) => {
      const dir = realpathSync(temp);
      readOwnerAndDacl.mockImplementation((target) =>
        target === dir ? facts({ complete: false }) : facts(),
      );
      emit.mockImplementation(() => {
        throw new Error("log sink unavailable");
      });

      expect(() => assertPrivateWindowsWrapKeyDirectory(dir)).toThrow("unsafe Windows ACL");
    });
  });
});
