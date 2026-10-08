// Exercises real config mutation, plugin validation, reload, and node file I/O.
import fs from "node:fs/promises";
import path from "node:path";
import type { OpenClawPluginNodeInvokePolicyContext } from "openclaw/plugin-sdk/plugin-entry";
import {
  clearConfigCache,
  clearRuntimeConfigSnapshot,
  getRuntimeConfig,
} from "openclaw/plugin-sdk/runtime-config-snapshot";
import { withTempHome } from "openclaw/plugin-sdk/test-env";
import { afterEach, describe, expect, it, vi } from "vitest";
import { handleFileFetch } from "../node-host/file-fetch.js";
import { handleFileWrite } from "../node-host/file-write.js";
import { createFileTransferNodeInvokePolicy } from "./node-invoke-policy.js";
import { evaluateFilePolicy, persistAllowAlways } from "./policy.js";

// Audit transport is orthogonal; the policy, mutation, validation, and node
// handlers below are real. Never write test events into the operator's log.
vi.mock("./audit.js", () => ({ appendFileTransferAudit: vi.fn(async () => undefined) }));

function reloadConfig() {
  clearRuntimeConfigSnapshot();
  clearConfigCache();
  return getRuntimeConfig();
}

afterEach(() => {
  clearRuntimeConfigSnapshot();
  clearConfigCache();
  vi.restoreAllMocks();
});

describe("file-transfer persistent exact approvals", () => {
  it.each(
    ["Shared Name", "*"].flatMap((displayName) =>
      (["read", "write"] as const).map((kind) => ({ displayName, kind })),
    ),
  )(
    "binds $kind grants to node ID when display name is $displayName",
    async ({ displayName, kind }) => {
      await withTempHome(
        async (home) => {
          const configPath = path.join(home, ".openclaw", "openclaw.json");
          const field = kind === "read" ? "allowReadExactPaths" : "allowWriteExactPaths";
          const inherited = {
            ask: kind === "read" ? "on-miss" : "always",
            allowReadPaths: ["/manual/**"],
            denyPaths: ["/denied/**"],
            maxBytes: 123,
            followSymlinks: true,
            [field]: ["/existing-literal"],
          };
          await fs.writeFile(
            configPath,
            JSON.stringify({
              plugins: {
                entries: {
                  "file-transfer": {
                    enabled: true,
                    config: { nodes: { [displayName]: inherited } },
                  },
                },
              },
            }),
          );
          reloadConfig();
          await persistAllowAlways({
            nodeId: "n1",
            nodeDisplayName: displayName,
            kind,
            path: "/approved.txt",
          });
          reloadConfig();
          expect(
            evaluateFilePolicy({
              nodeId: "n2",
              nodeDisplayName: displayName,
              kind,
              path: "/approved.txt",
            }),
          ).not.toMatchObject({ ok: true, reason: "matched-allow" });
          expect(
            evaluateFilePolicy({
              nodeId: "n1",
              nodeDisplayName: displayName,
              kind,
              path: "/approved.txt",
            }),
          ).toMatchObject({
            ok: true,
            maxBytes: 123,
            followSymlinks: true,
            reason: kind === "read" ? "matched-allow" : "ask-always",
          });
          expect(
            evaluateFilePolicy({
              nodeId: "n1",
              nodeDisplayName: displayName,
              kind,
              path: "/denied/file",
            }),
          ).toMatchObject({ ok: false, askable: false });
          const persisted = JSON.parse(await fs.readFile(configPath, "utf8"));
          const nodes = persisted.plugins.entries["file-transfer"].config.nodes;
          expect(nodes[displayName]).toEqual(inherited);
          expect(nodes.n1).toEqual({
            ...inherited,
            [field]: ["/existing-literal", "/approved.txt"],
          });
        },
        {
          env: {
            OPENCLAW_CONFIG_PATH: (home) => path.join(home, ".openclaw", "openclaw.json"),
            OPENCLAW_DISABLE_BUNDLED_PLUGINS: undefined,
            OPENCLAW_NIX_MODE: undefined,
          },
        },
      );
    },
  );

  it.each(["read", "write"] as const)(
    "%s approval survives real config write/reload without authorizing a brace alternative",
    async (kind) => {
      await withTempHome(
        async (home) => {
          const root = await fs.realpath(home);
          const configPath = path.join(root, ".openclaw", "openclaw.json");
          const approvedPath = path.join(root, "{public,secret}.txt");
          const otherPath = path.join(root, "secret.txt");
          await fs.writeFile(approvedPath, "approved");
          await fs.writeFile(otherPath, "not approved");
          const initial = {
            plugins: {
              entries: {
                "file-transfer": {
                  enabled: true,
                  config: { nodes: { n1: { ask: "on-miss" }, "*": { ask: "on-miss" } } },
                },
              },
            },
          };
          await fs.writeFile(configPath, JSON.stringify(initial));
          reloadConfig();
          const request = vi.fn().mockResolvedValue({ decision: "allow-always" });
          const invokeNode = vi.fn<OpenClawPluginNodeInvokePolicyContext["invokeNode"]>(
            async (input) => {
              const params = (input?.params ?? {}) as Record<string, unknown>;
              return {
                ok: true,
                payload:
                  kind === "read" ? await handleFileFetch(params) : await handleFileWrite(params),
              };
            },
          );
          const policy = createFileTransferNodeInvokePolicy();
          const ctx = (requestedPath: string): OpenClawPluginNodeInvokePolicyContext => ({
            nodeId: "n1",
            node: { nodeId: "n1" },
            command: kind === "read" ? "file.fetch" : "file.write",
            params: {
              path: requestedPath,
              contentBase64: Buffer.from("changed").toString("base64"),
              overwrite: true,
            },
            config: getRuntimeConfig(),
            pluginConfig: initial.plugins.entries["file-transfer"].config,
            approvals: { request },
            invokeNode,
          });
          expect(await policy.handle(ctx(approvedPath))).toMatchObject({
            ok: true,
            payload: {
              ok: true,
              path: approvedPath,
              ...(kind === "read" ? { base64: Buffer.from("approved").toString("base64") } : {}),
            },
          });
          expect(request).toHaveBeenCalledOnce();
          // Match behavior, not just storage: old code silently grants otherPath.
          expect(evaluateFilePolicy({ nodeId: "n1", kind, path: otherPath }).ok).toBe(false);
          const persisted = JSON.parse(await fs.readFile(configPath, "utf8"));
          const entry = persisted.plugins.entries["file-transfer"].config.nodes.n1;
          const field = kind === "read" ? "allowReadExactPaths" : "allowWriteExactPaths";
          expect(entry[field]).toEqual([approvedPath]);
          expect(entry.allowReadPaths).toBeUndefined();
          expect(entry.allowWritePaths).toBeUndefined();
          request.mockResolvedValue({ decision: "deny" });
          for (const reload of [false, true]) {
            if (reload) {
              reloadConfig();
            }
            request.mockClear();
            expect(await policy.handle(ctx(approvedPath))).toMatchObject({ ok: true });
            expect(request).not.toHaveBeenCalled();
            invokeNode.mockClear();
            expect(await policy.handle(ctx(otherPath))).toMatchObject({
              ok: false,
              code: "APPROVAL_DENIED",
            });
            expect(invokeNode).not.toHaveBeenCalled();
            expect(evaluateFilePolicy({ nodeId: "n2", kind, path: approvedPath }).ok).toBe(false);
            expect(
              evaluateFilePolicy({
                nodeId: "n1",
                kind: kind === "read" ? "write" : "read",
                path: approvedPath,
              }).ok,
            ).toBe(false);
          }
          expect(await fs.readFile(otherPath, "utf8")).toBe("not approved");
          if (kind === "write") {
            expect(await fs.readFile(approvedPath, "utf8")).toBe("changed");
          }
        },
        {
          env: {
            OPENCLAW_CONFIG_PATH: (home) => path.join(home, ".openclaw", "openclaw.json"),
            OPENCLAW_DISABLE_BUNDLED_PLUGINS: undefined,
            OPENCLAW_NIX_MODE: undefined,
          },
        },
      );
    },
  );

  it.each([
    ["/tmp/file*.txt", "/tmp/file-secret.txt"],
    ["/tmp/file?.txt", "/tmp/file1.txt"],
    ["/tmp/file[12].txt", "/tmp/file2.txt"],
    ["/tmp/@(one|two).txt", "/tmp/two.txt"],
    ["/tmp/{1..3}.txt", "/tmp/2.txt"],
    ["/tmp/a\\b.txt", "/tmp/a/b.txt"],
    ["C:\\files\\[12].txt", "C:/files/2.txt"],
    ["/tmp/trailing ", "/tmp/trailing"],
    ["~/file.txt", "/placeholder-for-home/file.txt"],
    ["/tmp/中文{甲,乙}.txt", "/tmp/中文乙.txt"],
    ["/tmp/directory", "/tmp/directory/child.txt"],
  ])("persists %s without authorizing %s", async (approvedPath, otherPath) => {
    await withTempHome(
      async (home) => {
        const deniedPath = approvedPath === "~/file.txt" ? path.join(home, "file.txt") : otherPath;
        const configPath = path.join(home, ".openclaw", "openclaw.json");
        await fs.writeFile(
          configPath,
          JSON.stringify({
            plugins: {
              entries: {
                "file-transfer": {
                  enabled: true,
                  config: {
                    nodes: { n1: { ask: "on-miss", allowReadPaths: ["/manual/**"] } },
                  },
                },
              },
            },
          }),
        );
        reloadConfig();
        await persistAllowAlways({ nodeId: "n1", kind: "read", path: approvedPath });
        await persistAllowAlways({ nodeId: "n1", kind: "read", path: approvedPath });
        reloadConfig();
        expect(evaluateFilePolicy({ nodeId: "n1", kind: "read", path: approvedPath }).ok).toBe(
          true,
        );
        expect(evaluateFilePolicy({ nodeId: "n1", kind: "read", path: deniedPath }).ok).toBe(false);
        expect(evaluateFilePolicy({ nodeId: "n1", kind: "read", path: "/manual/control" }).ok).toBe(
          true,
        );
        const persisted = JSON.parse(await fs.readFile(configPath, "utf8"));
        expect(persisted.plugins.entries["file-transfer"].config.nodes.n1).toMatchObject({
          allowReadPaths: ["/manual/**"],
          allowReadExactPaths: [approvedPath],
        });
      },
      {
        env: {
          OPENCLAW_CONFIG_PATH: (home) => path.join(home, ".openclaw", "openclaw.json"),
          OPENCLAW_DISABLE_BUNDLED_PLUGINS: undefined,
          OPENCLAW_NIX_MODE: undefined,
        },
      },
    );
  });
});
