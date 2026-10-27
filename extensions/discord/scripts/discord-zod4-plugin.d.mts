import type { Plugin } from "esbuild";

export function createDiscordZod4Plugin(): Promise<{
  plugin: Plugin;
  counts: () => { redirects: number; fallbacks: number };
}>;
