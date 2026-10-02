import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stageBackupSources } from "./backup-source-staging.js";
import { createBackupWrappingKeyFilter } from "./backup-wrapping-key-filter.js";

describe("backup descriptor staging", () => {
  afterEach(() => vi.restoreAllMocks());

  it.each(["leaf", "ancestor", "truncate", "during-read"])(
    "refuses a %s swap to an unchanged key after selection",
    async (kind) => {
      const temp = await fs.mkdtemp(path.join(os.tmpdir(), "backup-read-race-"));
      try {
        const sourceDir = path.join(temp, "source");
        const secretDir = path.join(temp, "secret");
        await fs.mkdir(sourceDir);
        await fs.mkdir(secretDir);
        const candidate = path.join(sourceDir, "wrap-key.b64");
        const key = path.join(secretDir, "wrap-key.b64");
        await fs.writeFile(candidate, "ordinary-data");
        await fs.writeFile(key, "fake-secret-key");
        const keys = await createBackupWrappingKeyFilter(secretDir);
        let swapped = false;
        await expect(
          stageBackupSources({
            directory: path.join(temp, "stage"),
            sources: [candidate],
            assertSafeRead: keys.assertSafeRead,
            filter: (file) => {
              if (file === candidate) {
                swapped = true;
              }
              return true;
            },
          }),
        ).resolves.toBeDefined();
        expect(swapped).toBe(true);
        const originalOpen = fs.open.bind(fs);
        vi.spyOn(fs, "open").mockImplementation(async (file, ...args) => {
          if (file === candidate) {
            if (kind === "leaf") {
              await fs.rename(candidate, `${candidate}.old`);
              await fs.symlink(key, candidate);
            } else if (kind === "ancestor") {
              await fs.rename(sourceDir, `${sourceDir}.old`);
              await fs.symlink(secretDir, sourceDir, "junction");
            } else if (kind === "truncate") {
              await fs.truncate(candidate, 0);
            }
          }
          return originalOpen(file, ...args);
        });
        await expect(
          stageBackupSources({
            directory: path.join(temp, "race-stage"),
            sources: [candidate],
            assertSafeRead: async (file, stat) => {
              await keys.assertSafeRead(file, stat);
              if (kind === "during-read") {
                await fs.truncate(candidate, 0);
              }
            },
            filter: () => true,
          }),
        ).rejects.toThrow();
        await keys.assertUnchanged();
      } finally {
        vi.restoreAllMocks();
        await fs.rm(temp, { recursive: true, force: true });
      }
    },
  );
});
