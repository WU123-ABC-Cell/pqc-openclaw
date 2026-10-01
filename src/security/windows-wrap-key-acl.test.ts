import { describe, expect, it } from "vitest";
import {
  isPrivateWindowsWrapKeyAcl,
  isStableWindowsWrapKeyAncestorAcl,
} from "./windows-wrap-key-acl.js";

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
