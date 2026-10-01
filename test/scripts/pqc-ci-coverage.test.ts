import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

describe("PQC CI product boundary coverage", () => {
  it("triggers broad CI on the fork default branch", () => {
    const workflow = parse(readFileSync(".github/workflows/ci.yml", "utf8"));
    expect(workflow.on.push.branches).toContain("master");
    expect(workflow.on.push.branches).toContain("main");
  });

  it("runs pairing, byte-budget delivery, and identity regression suites without conditional skips", () => {
    const workflow = parse(readFileSync(".github/workflows/pqc-ci.yml", "utf8"));
    expect(workflow.on.push.branches).toContain("master");
    const step = workflow.jobs["pqc-core"].steps.find(
      (candidate: { name?: string }) => candidate.name === "Run focused PQC integration tests",
    );
    expect(step).toBeDefined();
    expect(step.if).toBeUndefined();
    expect(step["continue-on-error"]).toBeUndefined();
    const command = step.run.split(/\s+/u);
    for (const suite of [
      "src/pairing/pairing-challenge.test.ts",
      "extensions/nostr/src/channel.inbound.test.ts",
      "extensions/nostr/src/channel.outbound.test.ts",
      "extensions/nostr/src/nostr-bus.inbound.test.ts",
      "extensions/nostr/src/nostr-bus.e2e.test.ts",
      "src/security/wrap-key-cli.test.ts",
      "src/security/windows-wrap-key-acl.test.ts",
      "src/infra/fs-safe-defaults.test.ts",
      "src/infra/device-identity.state-dir.test.ts",
    ]) {
      expect(command).toContain(suite);
      expect(readFileSync(suite, "utf8").length).toBeGreaterThan(0);
    }
  });
});
