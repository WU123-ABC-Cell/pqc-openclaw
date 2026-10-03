import type { Command } from "commander";
import { defaultRuntime } from "../runtime.js";
import { applyParentDefaultHelpAction } from "./program/parent-default-help.js";

export function registerWrapKeyCli(program: Command): void {
  const wrapKey = program.command("wrap-key").description("Inspect device wrapping-key health");
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
}
