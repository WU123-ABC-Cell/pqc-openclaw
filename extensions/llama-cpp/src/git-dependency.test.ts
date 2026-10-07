import { execFileSync } from "node:child_process";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Resolve through the optional consumer, not a potentially different root copy.
const requireFromPlugin = createRequire(import.meta.url);
const requireFromLlama = createRequire(requireFromPlugin.resolve("node-llama-cpp"));
const gitModule = (await import(
  pathToFileURL(requireFromLlama.resolve("simple-git")).href
)) as typeof import("simple-git");

let root: string;
let source: string;
let env: NodeJS.ProcessEnv;

function git(args: string[], cwd = source): string {
  return execFileSync("git", args, { cwd, env, encoding: "utf8", timeout: 15_000 });
}

beforeAll(async () => {
  root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "llama-git-security-")));
  source = path.join(root, "source");
  const home = path.join(root, "home");
  await fs.mkdir(source);
  await fs.mkdir(home);
  env = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    HOME: home,
    USERPROFILE: home,
    XDG_CONFIG_HOME: home,
    TERM: "xterm",
  };
  git(["init", "-q"]);
  git(["config", "user.name", "Security Fixture"]);
  git(["config", "user.email", "fixture@example.invalid"]);
  await fs.writeFile(path.join(source, "sample.txt"), "before\n");
  git(["add", "sample.txt"]);
  git(["commit", "-qm", "initial"]);
});

afterAll(async () => {
  if (root) {
    await fs.rm(root, { recursive: true, force: true });
  }
});

describe("llama.cpp Git dependency boundary", () => {
  it.each([
    ["VISUAL", "environment"],
    ["trailer.audit.cmd", "config"],
    ["trailer.audit.command", "config"],
    ["include.path", "config"],
    ["includeIf.gitdir:.path", "config"],
  ] as const)("rejects unsafe %s before spawning Git", async (key, kind) => {
    const instance = gitModule.simpleGit({
      baseDir: source,
      ...(kind === "config" ? { config: [`${key}=fixture-command`] } : {}),
    });
    instance.env({ ...env, ...(kind === "environment" ? { [key]: "fixture-command" } : {}) });
    await expect(instance.raw(["status", "--porcelain"])).rejects.toBeInstanceOf(
      gitModule.GitPluginError,
    );
  });

  it.each(["--receive-p", "--receive-pa", "--exe"])(
    "prevents Git from executing abbreviated %s",
    async (flag) => {
      const marker = path.join(root, `${flag}.marker`).replaceAll("\\", "/");
      const escapedMarker = marker.replaceAll("'", "'\\''");
      // Harmless marker: a later Git error alone does not prove no command ran.
      const command = `printf invoked > '${escapedMarker}'; false`;
      await expect(
        gitModule
          .simpleGit(source)
          .env(env)
          .raw(["push", `${flag}=${command}`, source, "HEAD"]),
      ).rejects.toThrow();
      await expect(fs.access(marker)).rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  it("preserves the consumer's local bundle clone, remote removal, and patch application", async () => {
    const bundle = path.join(root, "source.bundle");
    const dest = path.join(root, "clone");
    git(["bundle", "create", bundle, "HEAD"]);
    await gitModule.simpleGit(root).env(env).clone(bundle, dest, { "--quiet": null });
    const cloned = gitModule.simpleGit(dest).env(env);
    await cloned.removeRemote("origin");
    expect(await cloned.getRemotes()).toEqual([]);
    const patch = path.join(root, "sample.diff");
    await fs.writeFile(
      patch,
      "diff --git a/sample.txt b/sample.txt\n--- a/sample.txt\n+++ b/sample.txt\n@@ -1 +1 @@\n-before\n+after\n",
    );
    await cloned.applyPatch(patch, { "--ignore-whitespace": null });
    expect(await fs.readFile(path.join(dest, "sample.txt"), "utf8")).toBe("after\n");
    expect((await cloned.status()).modified).toEqual(["sample.txt"]);
    await expect(cloned.raw(["invalid-fixture-command"])).rejects.toBeInstanceOf(
      gitModule.GitError,
    );
  });
});
