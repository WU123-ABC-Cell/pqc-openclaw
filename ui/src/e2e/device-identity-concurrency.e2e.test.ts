import { chromium, type Browser, type Page } from "playwright";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  canRunPlaywrightChromium,
  resolvePlaywrightChromiumExecutablePath,
  startControlUiE2eServer,
  type ControlUiE2eServer,
} from "../test-helpers/control-ui-e2e.ts";

const executablePath = resolvePlaywrightChromiumExecutablePath(chromium.executablePath());
const available = canRunPlaywrightChromium(executablePath);
const describeBrowser =
  available || process.env.OPENCLAW_UI_E2E_ALLOW_MISSING_CHROMIUM !== "1"
    ? describe
    : describe.skip;
const identityKey = "openclaw-device-identity-v2";
type IdentityTestWindow = Window & {
  loadIdentityForTest?: typeof import("../lib/nodes/index.ts").loadOrCreateDeviceIdentity;
  releaseIdentityDigest?: () => void;
};

async function installIdentityLoader(page: Page): Promise<void> {
  await page.addScriptTag({
    type: "module",
    content:
      "import { loadOrCreateDeviceIdentity } from '/src/lib/nodes/index.ts'; window.loadIdentityForTest = loadOrCreateDeviceIdentity;",
  });
  await page.waitForFunction(
    () => typeof (window as IdentityTestWindow).loadIdentityForTest === "function",
  );
}

describeBrowser("Control UI identity first-use coordination", () => {
  let browser: Browser;
  let server: ControlUiE2eServer;

  beforeAll(async () => {
    if (!available) {
      throw new Error(`Playwright Chromium is unavailable at ${executablePath}`);
    }
    server = await startControlUiE2eServer(undefined, { source: true });
    browser = await chromium.launch({ executablePath });
  }, 120_000);

  afterAll(async () => {
    await browser?.close();
    await server?.close();
  });

  it("returns one durable identity to two tabs racing on empty shared storage", async () => {
    const context = await browser.newContext();
    try {
      const first = await context.newPage();
      const second = await context.newPage();
      for (const page of [first, second]) {
        await page.route("**/identity-race-fixture", (route) =>
          route.fulfill({
            contentType: "text/html",
            body: "<!doctype html><title>identity race</title>",
          }),
        );
        await page.goto(`${server.baseUrl}identity-race-fixture`);
        await installIdentityLoader(page);
      }
      expect(await first.evaluate((key) => localStorage.getItem(key), identityKey)).toBeNull();

      const firstLoad = first.evaluate(async () => {
        const loadOrCreateDeviceIdentity = (window as IdentityTestWindow).loadIdentityForTest!;
        const subtle = crypto.subtle;
        const digest = subtle.digest.bind(subtle);
        let release!: () => void;
        const paused = new Promise<void>((resolve) => {
          release = resolve;
        });
        Object.defineProperty(window, "releaseIdentityDigest", {
          value: release,
          configurable: true,
        });
        Object.defineProperty(subtle, "digest", {
          configurable: true,
          value: async (...args: Parameters<typeof subtle.digest>) => {
            Object.defineProperty(window, "identityDigestWaiting", {
              value: true,
              configurable: true,
            });
            await paused;
            return digest(...args);
          },
        });
        return loadOrCreateDeviceIdentity();
      });
      await first.waitForFunction(() => "identityDigestWaiting" in window);
      const secondLoad = second.evaluate(async () => {
        return (window as IdentityTestWindow).loadIdentityForTest!();
      });
      await first.waitForFunction(async (key) => {
        const snapshot = await navigator.locks.query();
        return snapshot.pending?.some((lock) => lock.name === key) ?? false;
      }, identityKey);
      await first.evaluate(() => (window as IdentityTestWindow).releaseIdentityDigest!());
      const [a, b] = await Promise.all([firstLoad, secondLoad]);
      expect(b).toEqual(a);
      expect(
        JSON.parse(await first.evaluate((key) => localStorage.getItem(key) ?? "null", identityKey))
          .deviceId,
      ).toBe(a.deviceId);

      await Promise.all([first.reload(), second.reload()]);
      await Promise.all([installIdentityLoader(first), installIdentityLoader(second)]);
      const afterReload = await Promise.all(
        [first, second].map((page) =>
          page.evaluate(() => (window as IdentityTestWindow).loadIdentityForTest!()),
        ),
      );
      expect(afterReload).toEqual([a, a]);
    } finally {
      await context.close();
    }
  }, 90_000);

  it("reports unsupported browser coordination before creating an identity", async () => {
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      await page.route("**/identity-race-fixture", (route) =>
        route.fulfill({
          contentType: "text/html",
          body: "<!doctype html><title>identity race</title>",
        }),
      );
      await page.goto(`${server.baseUrl}identity-race-fixture`);
      await installIdentityLoader(page);
      const result = await page.evaluate(async () => {
        Object.defineProperty(navigator, "locks", { configurable: true, value: undefined });
        try {
          await (window as IdentityTestWindow).loadIdentityForTest!();
          return { error: null, stored: localStorage.getItem("openclaw-device-identity-v2") };
        } catch (error) {
          return {
            error: String(error),
            stored: localStorage.getItem("openclaw-device-identity-v2"),
          };
        }
      });
      expect(result.error).toContain("requires Web Locks");
      expect(result.stored).toBeNull();
    } finally {
      await context.close();
    }
  });
});
