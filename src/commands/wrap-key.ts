// PQC step 2.3.8: openclaw wrap-key CLI subcommand handlers.
import { randomBytes } from "node:crypto";
import {
  exportWrapKey,
  importWrapKey,
  serializeBackup,
  deserializeBackup,
  WrapKeyBackupError,
  type ExportOptions,
  type ImportOptions,
  type ExportedWrapKey,
} from "../security/wrap-key-backup.js";
import { getOrCreateDefaultWrappingProvider } from "../infra/device-identity-store-keyring-default.js";
import { createDefaultKeyringProvider, generateKeyId } from "../security/keyring-provider.js";
import { runWrapKeyHealthCheck } from "../security/wrap-key-health-check.js";
import {
  rotateDeviceIdentityWrappingKey,
  type RotateDeviceIdentityWrappingKeyOptions,
} from "../infra/state-migrations.rotate-wrapping-key.js";
import type { OpenClawStateDatabaseOptions } from "../state/openclaw-state-db.js";
import type { WrappingKeyProvider } from "../security/secret-wrapping.js";
import { defaultRuntime } from "../runtime.js";

export interface WrapKeyCommandContext {
  readonly env?: NodeJS.ProcessEnv;
  readonly cwd?: string;
  readonly stateDir?: string;
  readonly provider?: WrappingKeyProvider;
  readonly readPassphrase?: (prompt: string) => Promise<string>;
  readonly stdout?: (line: string) => void;
  readonly stderr?: (line: string) => void;
}

export interface WrapKeyCommandResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

const USAGE = `Usage: openclaw wrap-key <subcommand> [options]

Subcommands:
  export              Export the active wrap key to a passphrase-encrypted backup blob
  import <blob>       Import a backup blob and persist the key to disk
  rotate              Generate a new wrap key, rewrap all device identities (requires --confirm)
  status              Show wrap-key state (keyring + device identity wrap coverage)

Common options:
  --passphrase <pw>   Passphrase for export/import (otherwise prompted)
  --key-id <id>       Specific key id to export (default: active)
  --iterations <n>    PBKDF2 iteration count (default: 600000)
  --confirm           Required for 'rotate' to proceed
  --help, -h          Show this help
`;

function defaultStateOptions(ctx: WrapKeyCommandContext): OpenClawStateDatabaseOptions {
  const opts: OpenClawStateDatabaseOptions = {};
  if (ctx.env) (opts as { env?: NodeJS.ProcessEnv }).env = ctx.env;
  if (ctx.cwd) (opts as { cwd?: string }).cwd = ctx.cwd;
  return opts;
}

function getProvider(ctx: WrapKeyCommandContext): WrappingKeyProvider {
  if (ctx.provider) return ctx.provider;
  if (ctx.stateDir) {
    return createDefaultKeyringProvider({ dir: ctx.stateDir });
  }
  return getOrCreateDefaultWrappingProvider();
}

async function readPassphraseInteractive(
  ctx: WrapKeyCommandContext,
  prompt: string,
  provided: string | undefined,
): Promise<string> {
  if (provided !== undefined) return provided;
  if (ctx.readPassphrase) return await ctx.readPassphrase(prompt);
  return await new Promise<string>((resolve) => {
    defaultRuntime.question(prompt, (answer) => resolve(answer ?? ""));
  });
}

async function runExport(args: readonly string[], ctx: WrapKeyCommandContext): Promise<WrapKeyCommandResult> {
  let keyId: string | undefined;
  let passphrase: string | undefined;
  let iterations: number | undefined;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    if (a === "--key-id") keyId = args[++i];
    else if (a === "--passphrase") passphrase = args[++i];
    else if (a === "--iterations") iterations = Number(args[++i]);
    else return { exitCode: 2, stdout: "", stderr: `unknown flag: ${a}\n\n${USAGE}` };
  }
  const provider = getProvider(ctx);
  let key: Buffer;
  let resolvedKeyId: string;
  if (keyId) {
    const fetched = provider.getKeyById(keyId);
    if (!fetched) return { exitCode: 1, stdout: "", stderr: `unknown wrap key id: ${keyId}` };
    key = fetched;
    resolvedKeyId = keyId;
  } else {
    const active = provider.getActiveKey();
    key = active.key;
    resolvedKeyId = active.keyId;
  }
  const pw = await readPassphraseInteractive(ctx, "Passphrase: ", passphrase);
  if (pw.length === 0) {
    return { exitCode: 2, stdout: "", stderr: "passphrase required (use --passphrase or pipe stdin)" };
  }
  const exportOpts: ExportOptions = iterations ? { passphrase: pw, iterations } : { passphrase: pw };
  const blob = exportWrapKey(key, resolvedKeyId, exportOpts);
  const serialized = serializeBackup(blob);
  return { exitCode: 0, stdout: serialized + "\n", stderr: "" };
}

async function runImport(args: readonly string[], ctx: WrapKeyCommandContext): Promise<WrapKeyCommandResult> {
  let passphrase: string | undefined;
  const positional: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]!;
    if (a === "--passphrase") passphrase = args[++i];
    else if (a.startsWith("-")) return { exitCode: 2, stdout: "", stderr: `unknown flag: ${a}\n\n${USAGE}` };
    else positional.push(a);
  }
  const blob = positional[0];
  if (!blob) return { exitCode: 2, stdout: "", stderr: `usage: openclaw wrap-key import <blob>\n\n${USAGE}` };
  const pw = await readPassphraseInteractive(ctx, "Passphrase: ", passphrase);
  if (pw.length === 0) {
    return { exitCode: 2, stdout: "", stderr: "passphrase required (use --passphrase or pipe stdin)" };
  }
  let parsed: ExportedWrapKey;
  try {
    parsed = deserializeBackup(blob);
  } catch (err) {
    return { exitCode: 2, stdout: "", stderr: `invalid backup blob: ${err instanceof Error ? err.message : String(err)}` };
  }
  const importOpts: ImportOptions = { passphrase: pw };
  const provider = getProvider(ctx);
  try {
    const maybeImport = (provider as unknown as {
      importKey?: (b: ExportedWrapKey, o: ImportOptions) => { keyId: string; becameActive: boolean };
    }).importKey;
    if (typeof maybeImport === "function") {
      const result = maybeImport.call(provider, parsed, importOpts);
      return { exitCode: 0, stdout: `imported wrap key ${result.keyId} (became active: ${result.becameActive})\n`, stderr: "" };
    }
    importWrapKey(parsed, importOpts);
    return { exitCode: 0, stdout: `imported wrap key ${parsed.keyId} (provider does not persist; keep environment variable OPENCLAW_WRAP_KEY to use it)\n`, stderr: "" };
  } catch (err) {
    if (err instanceof WrapKeyBackupError) return { exitCode: 1, stdout: "", stderr: err.message };
    throw err;
  }
}

async function runRotate(args: readonly string[], ctx: WrapKeyCommandContext): Promise<WrapKeyCommandResult> {
  let confirm = false;
  for (const a of args) {
    if (a === "--confirm") confirm = true;
    else return { exitCode: 2, stdout: "", stderr: `unknown flag: ${a}\n\n${USAGE}` };
  }
  if (!confirm) {
    return { exitCode: 2, stdout: "", stderr: "refusing to rotate without --confirm: this rewraps every device identity in state.db.\nRun with --confirm to proceed." };
  }
  const provider = getProvider(ctx);
  const newKeyId = generateKeyId();
  const newKey = randomBytes(32);
  const addKey = (provider as unknown as { addKey?: (id: string, key: Buffer) => void }).addKey;
  if (typeof addKey === "function") addKey.call(provider, newKeyId, newKey);
  const newProvider: WrappingKeyProvider = {
    getActiveKey: () => ({ key: newKey, keyId: newKeyId }),
    getKeyById: (id) => (id === newKeyId ? newKey : provider.getKeyById(id)),
  };
  const rotateOpts: RotateDeviceIdentityWrappingKeyOptions = {
    ...defaultStateOptions(ctx),
    newProvider,
    newKeyId,
    oldProvider: provider,
  };
  const result = rotateDeviceIdentityWrappingKey(rotateOpts);
  return {
    exitCode: 0,
    stdout: `rotated ${result.rotatedRows} device identity row(s) from keys [${[...result.fromKeyIds].join(", ")}] to ${result.toKeyId}\n`,
    stderr: "",
  };
}

async function runStatus(args: readonly string[], ctx: WrapKeyCommandContext): Promise<WrapKeyCommandResult> {
  if (args.length > 0 && (args[0] === "--help" || args[0] === "-h")) {
    return { exitCode: 0, stdout: USAGE, stderr: "" };
  }
  const probe = await runWrapKeyHealthCheck(defaultStateOptions(ctx));
  if (!probe.ok) return { exitCode: 1, stdout: "", stderr: `wrap-key probe failed: ${probe.error}` };
  const lines: string[] = [];
  lines.push("wrap-key status");
  lines.push(`  total device identities:  ${probe.probe.totalIdentities}`);
  lines.push(`  wrapped (PQC 2.3):       ${probe.probe.wrappedIdentities}`);
  lines.push(`  legacy (no wrap cols):   ${probe.probe.legacyIdentities}`);
  if (probe.probe.missingKeyIds.length > 0) {
    lines.push(`  MISSING key ids:         ${probe.probe.missingKeyIds.join(", ")}`);
    lines.push("  -> run `openclaw wrap-key import <blob>` to restore missing keys");
  }
  for (const f of probe.findings) {
    lines.push(`  [${f.severity}] ${f.message}`);
    if (f.fixHint) lines.push(`      fix: ${f.fixHint}`);
  }
  const hasError = probe.findings.some(
    (f) => f.severity === "error" && f.message.includes("not in any keyring"),
  );
  return {
    exitCode: hasError ? 1 : 0,
    stdout: lines.join("\n") + "\n",
    stderr: "",
  };
}

export async function runWrapKeyCommand(
  args: readonly string[],
  ctx: WrapKeyCommandContext = {},
): Promise<WrapKeyCommandResult> {
  const [sub, ...rest] = args;
  if (!sub || sub === "--help" || sub === "-h" || sub === "help") {
    return { exitCode: 0, stdout: USAGE, stderr: "" };
  }
  try {
    switch (sub) {
      case "export": return await runExport(rest, ctx);
      case "import": return await runImport(rest, ctx);
      case "rotate": return await runRotate(rest, ctx);
      case "status": return await runStatus(rest, ctx);
      default: return { exitCode: 2, stdout: "", stderr: `unknown subcommand: ${sub}\n\n${USAGE}` };
    }
  } catch (err) {
    return { exitCode: 1, stdout: "", stderr: `wrap-key ${sub} failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
