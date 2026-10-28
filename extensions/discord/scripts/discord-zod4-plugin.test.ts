import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { build as esbuild } from "esbuild";
import { withTempDir } from "openclaw/plugin-sdk/test-env";
import { expect, it } from "vitest";
import { createDiscordZod4Plugin } from "./discord-zod4-plugin.mjs";

it("builds Discord SDK schemas with Zod 4 and retains unknown-scope fallback", async () => {
  await withTempDir("openclaw-discord-zod4-", async (rootDir) => {
    const require = createRequire(import.meta.url);
    const sdkDir = path.dirname(require.resolve("@discord/embedded-app-sdk/package.json"));
    const migration = await createDiscordZod4Plugin();
    const schemaPath = path.join(rootDir, "schemas.mjs");
    const result = await esbuild({
      entryPoints: [path.join(sdkDir, "output/generated/schemas.mjs")],
      bundle: true,
      platform: "node",
      format: "esm",
      outfile: schemaPath,
      write: false,
      metafile: true,
      plugins: [migration.plugin],
    });
    const inputs = Object.keys(result.metafile.inputs);
    expect(inputs.some((input) => input.includes("/lib/zod/"))).toBe(false);
    expect(inputs.some((input) => input.includes("/zod/v4/"))).toBe(true);
    expect(migration.counts()).toMatchObject({ fallbacks: 1 });
    const output = result.outputFiles[0];
    if (!output) {
      throw new Error("esbuild did not produce a Discord SDK schema bundle");
    }
    fs.writeFileSync(schemaPath, output.text);
    const { AuthenticateResponseSchema } = await import(pathToFileURL(schemaPath).href);
    const parsed = AuthenticateResponseSchema.safeParse({
      access_token: "token",
      user: { username: "u", discriminator: "0", id: "1", public_flags: 0 },
      scopes: ["unknown"],
      expires: "2026-10-25T00:00:00Z",
      application: { description: "test", icon: null, id: "1", name: "test" },
    });
    expect(parsed.success).toBe(true);
    expect(parsed.data.scopes).toEqual([-1]);
  });
});
