// PQC step 2.3.8: register the `openclaw wrap-key` command.
import type { Command } from "commander";
import { formatDocsLink } from "../../../packages/terminal-core/src/links.js";
import { theme } from "../../../packages/terminal-core/src/theme.js";
import { runCommandWithRuntime } from "../cli-utils.js";
import { runWrapKeyCommand } from "../../commands/wrap-key.js";
import { defaultRuntime } from "../../runtime.js";

export function registerWrapKeyCommand(program: Command): void {
  const wrapKey = program
    .command("wrap-key")
    .description("PQC wrap-key management: export, import, rotate, status")
    .addHelpText(
      "after",
      () =>
        `\n${theme.muted("Docs:")} ${formatDocsLink("/cli/wrap-key", "docs.openclaw.ai/cli/wrap-key")}\n`,
    );

  wrapKey
    .command("export")
    .description("Export the active wrap key to a passphrase-encrypted backup blob")
    .option("--passphrase <pw>", "Passphrase (otherwise prompted)")
    .option("--key-id <id>", "Specific key id (default: active)")
    .option("--iterations <n>", "PBKDF2 iteration count (default: 600000)", (v) => Number(v))
    .action(async (options) => {
      const args = ["export"];
      if (options.passphrase) args.push("--passphrase", options.passphrase);
      if (options.keyId) args.push("--key-id", options.keyId);
      if (options.iterations) args.push("--iterations", String(options.iterations));
      const result = await runWrapKeyCommand(args);
      if (result.stdout) defaultRuntime.log(result.stdout);
      if (result.stderr) defaultRuntime.error(result.stderr);
      if (result.exitCode !== 0) process.exit(result.exitCode);
    });

  wrapKey
    .command("import <blob>")
    .description("Import a backup blob and persist the key to disk")
    .option("--passphrase <pw>", "Passphrase (otherwise prompted)")
    .action(async (blob, options) => {
      const args = ["import", blob];
      if (options.passphrase) args.push("--passphrase", options.passphrase);
      const result = await runWrapKeyCommand(args);
      if (result.stdout) defaultRuntime.log(result.stdout);
      if (result.stderr) defaultRuntime.error(result.stderr);
      if (result.exitCode !== 0) process.exit(result.exitCode);
    });

  wrapKey
    .command("rotate")
    .description("Generate a new wrap key and rewrap all device identities (requires --confirm)")
    .option("--confirm", "Required to proceed; rotation rewrites every device identity")
    .action(async (options) => {
      const args = ["rotate"];
      if (options.confirm) args.push("--confirm");
      const result = await runWrapKeyCommand(args);
      if (result.stdout) defaultRuntime.log(result.stdout);
      if (result.stderr) defaultRuntime.error(result.stderr);
      if (result.exitCode !== 0) process.exit(result.exitCode);
    });

  wrapKey
    .command("status")
    .description("Show wrap-key state (keyring + device identity wrap coverage)")
    .action(async () => {
      const result = await runWrapKeyCommand(["status"]);
      if (result.stdout) defaultRuntime.log(result.stdout);
      if (result.stderr) defaultRuntime.error(result.stderr);
      if (result.exitCode !== 0) process.exit(result.exitCode);
    });
}
