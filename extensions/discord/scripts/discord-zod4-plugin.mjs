import fs from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

// Resolve both packages from the plugin that owns the browser SDK dependency.
const require = createRequire(import.meta.url);

/** Replace the SDK's bundled Zod 3 with the patched Zod 4 used by this workspace. */
export async function createDiscordZod4Plugin() {
  const sdkManifestPath = require.resolve("@discord/embedded-app-sdk/package.json");
  const sdkManifest = JSON.parse(await fs.readFile(sdkManifestPath, "utf8"));
  if (sdkManifest.version !== "2.5.0") {
    throw new Error(`Review Discord SDK Zod migration for version ${sdkManifest.version}`);
  }
  const sdkOutputDir = path.join(path.dirname(sdkManifestPath), "output");
  const zodManifestPath = require.resolve("zod/package.json");
  const zodManifest = JSON.parse(await fs.readFile(zodManifestPath, "utf8"));
  if (zodManifest.version !== "4.6.6") {
    throw new Error(`Review Discord SDK Zod migration for Zod ${zodManifest.version}`);
  }
  const zodEntry = path.join(path.dirname(zodManifestPath), "index.js");
  const sdkZodUtils = path.join(sdkOutputDir, "utils/zodUtils.mjs");
  let redirects = 0;
  let fallbacks = 0;

  return {
    counts: () => ({ redirects, fallbacks }),
    plugin: {
      name: "discord-sdk-zod4-migration",
      setup(builder) {
        builder.onResolve({ filter: /lib[\\/]zod[\\/]lib[\\/]index\.mjs$/ }, (args) => {
          if (!args.importer.startsWith(`${sdkOutputDir}${path.sep}`)) {
            throw new Error(`Unexpected Discord SDK Zod import from ${args.importer}`);
          }
          redirects += 1;
          return { path: zodEntry };
        });
        builder.onLoad({ filter: /[\\/]utils[\\/]zodUtils\.mjs$/ }, async (args) => {
          if (args.path !== sdkZodUtils) {
            throw new Error(`Unexpected Discord SDK Zod helper at ${args.path}`);
          }
          const original = await fs.readFile(args.path, "utf8");
          const before = "return schema._def.defaultValue();";
          if (original.split(before).length !== 2) {
            throw new Error("Discord SDK default fallback changed; review Zod 4 migration");
          }
          fallbacks += 1;
          return {
            contents: original.replace(
              before,
              'const value = schema._def.defaultValue; return typeof value === "function" ? value() : value;',
            ),
            loader: "js",
          };
        });
      },
    },
  };
}
