import type { Command } from "commander";
import { defaultRuntime } from "../runtime.js";
import { applyParentDefaultHelpAction } from "./program/parent-default-help.js";

export function registerWrapKeyCli(program: Command): void {
  const wrapKey = program
    .command("wrap-key")
    .description("Inspect and prepare device wrapping keys");
  applyParentDefaultHelpAction(wrapKey);
  wrapKey
    .command("status")
    .description("Check the active wrapping key and one stored identity without changing state")
    .option(
      "--identity-key <key>",
      "Stored identity to check (not an all-identities scan)",
      "primary",
    )
    .option("--json", "Output JSON", false)
    .action(async (opts: { identityKey: string; json: boolean }) => {
      const { runWrapKeyStatus } = await import("../commands/wrap-key-status.js");
      const ok = await runWrapKeyStatus(opts);
      if (!ok) {
        defaultRuntime.exit(1, { resetStream: process.stderr });
      }
    });
  wrapKey
    .command("prepare")
    .description("Create an independent private wrapping key without activating it")
    .requiredOption("--key-id <id>", "New immutable key ID (ASCII letters, digits, _ or -)")
    .option("--json", "Output JSON", false)
    .action(async (opts: { keyId: string; json: boolean }) => {
      const { runWrapKeyPrepare } = await import("../commands/wrap-key-prepare.js");
      if (!runWrapKeyPrepare(opts)) {
        defaultRuntime.exit(1, { resetStream: process.stderr });
      }
    });
  wrapKey
    .command("activate")
    .description("Offline activation of the v7 identity write fence")
    .requiredOption("--receipt-id <id>", "Stable recovery receipt ID")
    .option("--offline", "Confirm every state writer is stopped", false)
    .option("--json", "Output JSON", false)
    .action(async (opts: { receiptId: string; offline: boolean; json: boolean }) => {
      const { runWrapKeyActivate } = await import("../commands/wrap-key-offline.js");
      if (!(await runWrapKeyActivate(opts))) {
        defaultRuntime.exit(1, { resetStream: process.stderr });
      }
    });
  wrapKey
    .command("rotate")
    .description("Offline rewrap of every identity using a prepared key")
    .requiredOption("--receipt-id <id>", "Stable recovery receipt ID")
    .requiredOption("--key-id <id>", "Previously prepared target key ID")
    .option("--offline", "Confirm every state writer is stopped", false)
    .option("--json", "Output JSON", false)
    .action(async (opts: { receiptId: string; keyId: string; offline: boolean; json: boolean }) => {
      const { runWrapKeyRotate } = await import("../commands/wrap-key-offline.js");
      if (!(await runWrapKeyRotate(opts))) {
        defaultRuntime.exit(1, { resetStream: process.stderr });
      }
    });
  wrapKey
    .command("recover")
    .description(
      "Verify receipt, CLI key selection and rows offline; does not verify a running gateway",
    )
    .requiredOption("--receipt-id <id>", "Rotation receipt ID")
    .requiredOption("--key-id <id>", "Prepared target key ID")
    .option("--offline", "Confirm every state writer is stopped", false)
    .option("--json", "Output JSON", false)
    .action(async (opts: { receiptId: string; keyId: string; offline: boolean; json: boolean }) => {
      const { runWrapKeyRecover } = await import("../commands/wrap-key-offline.js");
      if (!(await runWrapKeyRecover(opts))) {
        defaultRuntime.exit(1, { resetStream: process.stderr });
      }
    });
}
