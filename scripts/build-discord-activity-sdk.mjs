#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { createDiscordZod4Plugin } from "../extensions/discord/scripts/discord-zod4-plugin.mjs";
import { writeGeneratedTextAsset } from "./lib/generated-text-asset.mjs";

const modulePath = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(modulePath), "..");
const discordDir = path.join(repoRoot, "extensions/discord");
const outputPath = path.join(repoRoot, "extensions/discord/assets/embedded-app-sdk.mjs");

/** Builds the browser SDK bundle without rewriting an identical generated asset. */
export async function buildDiscordActivitySdk(params = {}) {
  const buildImpl = params.build ?? build;
  const targetPath = params.outputPath ?? outputPath;
  const zod4Migration = params.build ? null : await createDiscordZod4Plugin();
  const result = await buildImpl({
    entryPoints: ["@discord/embedded-app-sdk"],
    absWorkingDir: discordDir,
    bundle: true,
    platform: "browser",
    target: "es2020",
    format: "esm",
    minify: true,
    legalComments: "none",
    outfile: targetPath,
    write: false,
    ...(zod4Migration ? { metafile: true, plugins: [zod4Migration.plugin] } : {}),
  });

  if (zod4Migration) {
    const { redirects, fallbacks } = zod4Migration.counts();
    const inputs = Object.keys(result.metafile?.inputs ?? {}).map((input) =>
      input.replaceAll("\\", "/"),
    );
    if (
      redirects === 0 ||
      fallbacks !== 1 ||
      inputs.some((input) => input.includes("/lib/zod/")) ||
      !inputs.some((input) => input.includes("/zod/v4/"))
    ) {
      throw new Error("Discord SDK bundle did not replace its bundled Zod 3 with Zod 4");
    }
  }

  const outputFile = result.outputFiles?.[0];
  if (!outputFile) {
    throw new Error("esbuild did not produce the Discord Embedded App SDK bundle");
  }

  return writeGeneratedTextAsset(targetPath, outputFile.text);
}

if (process.argv[1] === modulePath) {
  await buildDiscordActivitySdk();
}
