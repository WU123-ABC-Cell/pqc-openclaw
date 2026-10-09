import path from "node:path";
import ts from "typescript";
import { expect, it } from "vitest";

it("emits an inferred public SecretRef setup CLI consumer declaration", () => {
  const repoRoot = process.cwd();
  const config = ts.readConfigFile(path.join(repoRoot, "tsconfig.json"), ts.sys.readFile);
  expect(config.error).toBeUndefined();
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, repoRoot);
  expect(parsed.errors).toEqual([]);

  const fileName = path
    .join(repoRoot, "src", "plugin-sdk", "secret-ref-consumer-fixture.ts")
    .replaceAll(path.sep, "/");
  const source = `
    import { createPluginSecretRefSetupCli } from "openclaw/plugin-sdk/secret-ref-runtime";
    export const setupCli = createPluginSecretRefSetupCli({
      productName: "Fixture",
      secretIdLabel: "Fixture secret id",
      secretIdPlaceholder: "fixture-secret-id",
      defaultProviderAlias: "fixture",
      pluginIntegration: { pluginId: "fixture", integrationId: "fixture" },
      normalizeSecretId: (_label, value) => value,
      defaultPlanPath: () => "fixture-plan.json",
    });
  `;
  const options: ts.CompilerOptions = {
    ...parsed.options,
    incremental: false,
    noEmit: false,
    // Diagnostics below are authoritative for this consumer; do not recheck the entire host graph.
    noEmitOnError: false,
    declaration: true,
    emitDeclarationOnly: true,
    outDir: path.join(repoRoot, ".artifacts", "secretref-declarations"),
  };
  const host = ts.createCompilerHost(options);
  const readFile = host.readFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  host.readFile = (candidate) => (candidate === fileName ? source : readFile(candidate));
  host.fileExists = (candidate) => candidate === fileName || fileExists(candidate);
  const program = ts.createProgram([fileName], options, host);
  const consumer = program.getSourceFile(fileName);
  expect(consumer).toBeDefined();

  const diagnostics = ts.getPreEmitDiagnostics(program, consumer);
  expect(
    diagnostics.map((diagnostic) => ({
      code: diagnostic.code,
      message: ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
    })),
  ).toEqual([]);

  const declarations = new Map<string, string>();
  // Emit the real consumer through the public SDK path without writing fixture/artifact files.
  const emitted = program.emit(
    consumer,
    (name, content) => declarations.set(name, content),
    undefined,
    true,
  );
  expect(emitted.emitSkipped).toBe(false);
  expect(emitted.diagnostics).toEqual([]);
  const declaration = [...declarations.entries()].find(([name]) =>
    name.endsWith("secret-ref-consumer-fixture.d.ts"),
  )?.[1];
  expect(declaration).toContain("export declare const setupCli");
  expect(declaration).toContain("SecretRefSetupCommand");
});
