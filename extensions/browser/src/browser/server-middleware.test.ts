import { EventEmitter } from "node:events";
import http from "node:http";
import type { Express, NextFunction, Request, Response } from "express";
import express from "express";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  installBrowserAuthMiddleware,
  installBrowserCommonMiddleware,
} from "./server-middleware.js";

type Middleware = (req: Request, res: Response, next: NextFunction) => void;

let server: http.Server | undefined;

async function startMiddlewareTestServer(
  trustProxy?: string | string[],
): Promise<{ url: string; getRouteCalls: () => number }> {
  const app = express();
  if (trustProxy !== undefined) {
    app.set("trust proxy", trustProxy);
  }
  let routeCalls = 0;
  installBrowserCommonMiddleware(app);
  installBrowserAuthMiddleware(app, { token: "test-token" });
  app.get("/identity", (req, res) => {
    res.json({ ip: req.ip, ips: req.ips });
  });
  app.post("/mutate", (req, res) => {
    routeCalls += 1;
    res.status(200).json({ body: req.body });
  });

  server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve) => {
    server?.once("listening", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("expected TCP test server address");
  }
  return {
    url: `http://127.0.0.1:${address.port}`,
    getRouteCalls: () => routeCalls,
  };
}

afterEach(async () => {
  const current = server;
  server = undefined;
  if (!current) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    current.close((error) => (error ? reject(error) : resolve()));
  });
});

describe("installBrowserCommonMiddleware", () => {
  it("shadows native request signals with the browser response-lifetime signal", () => {
    const middleware: Middleware[] = [];
    const app = {
      use: vi.fn((...handlers: unknown[]) => {
        for (const handler of handlers) {
          if (typeof handler === "function") {
            middleware.push(handler as Middleware);
          }
        }
        return app;
      }),
    } as unknown as Express;
    installBrowserCommonMiddleware(app);

    const nativeController = new AbortController();
    const req = new EventEmitter() as EventEmitter & Request;
    const requestPrototype = Object.create(Object.getPrototypeOf(req)) as object;
    Object.defineProperty(requestPrototype, "signal", {
      configurable: true,
      get: () => nativeController.signal,
    });
    Object.setPrototypeOf(req, requestPrototype);

    const res = new EventEmitter() as EventEmitter & Response;
    Object.defineProperty(res, "writableEnded", { value: false, writable: true });
    const next = vi.fn();
    const commonMiddleware = middleware[0];
    if (!commonMiddleware) {
      throw new Error("browser common middleware was not installed");
    }

    commonMiddleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(Object.hasOwn(req, "signal")).toBe(true);
    expect(req.signal).not.toBe(nativeController.signal);
    expect(req.signal.aborted).toBe(false);

    req.emit("aborted");
    expect(req.signal.aborted).toBe(true);
    expect(req.signal.reason).toEqual(new Error("request aborted"));
  });

  it("rejects cross-site mutations before JSON body parsing", async () => {
    const { url, getRouteCalls } = await startMiddlewareTestServer();

    const response = await fetch(`${url}/mutate`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://evil.example",
      },
      body: "{not json",
    });

    expect(response.status).toBe(403);
    expect(await response.text()).toBe("Forbidden");
    expect(getRouteCalls()).toBe(0);
  });

  it("still parses allowed JSON requests after the mutation guard", async () => {
    const { url, getRouteCalls } = await startMiddlewareTestServer();

    const response = await fetch(`${url}/mutate`, {
      method: "POST",
      headers: {
        authorization: "Bearer test-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ ok: true }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ body: { ok: true } });
    expect(getRouteCalls()).toBe(1);
  });

  it.each([
    { trustProxy: "::ffff:10.0.0.0/8" },
    { trustProxy: ["::ffff:10.0.0.0/8", "2001:db8::/32"] },
    { trustProxy: "::/1" },
    { trustProxy: ["::/1", "2001:db8::/32"] },
  ])("does not trust an IPv4 socket via IPv6-only ranges: $trustProxy", async ({ trustProxy }) => {
    // These configurations exercise the dependency boundary; production keeps Express's default.
    const { url } = await startMiddlewareTestServer(trustProxy);
    const response = await fetch(`${url}/identity`, {
      headers: {
        authorization: "Bearer test-token",
        "x-forwarded-for": "203.0.113.9",
      },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ip: "127.0.0.1", ips: [] });
  });

  it.each(["127.0.0.0/8", "::ffff:127.0.0.0/104"])(
    "preserves correctly configured proxy trust: %s",
    async (trustProxy) => {
      const { url } = await startMiddlewareTestServer(trustProxy);
      const response = await fetch(`${url}/identity`, {
        headers: {
          authorization: "Bearer test-token",
          "x-forwarded-for": "203.0.113.9",
        },
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ ip: "203.0.113.9", ips: ["203.0.113.9"] });
    },
  );

  it("keeps forwarded identity headers outside default browser authentication", async () => {
    const { url } = await startMiddlewareTestServer();
    const headers = {
      "x-forwarded-for": "127.0.0.1",
      "x-real-ip": "127.0.0.1",
      "x-forwarded-host": "localhost",
    };
    const missingAuth = await fetch(`${url}/identity`, { headers });
    expect(missingAuth.status).toBe(401);
    const badAuth = await fetch(`${url}/identity`, {
      headers: { ...headers, authorization: "Bearer wrong-token" },
    });
    expect(badAuth.status).toBe(401);
    const authorized = await fetch(`${url}/identity`, {
      headers: { ...headers, authorization: "Bearer test-token" },
    });
    expect(authorized.status).toBe(200);
    expect(await authorized.json()).toEqual({ ip: "127.0.0.1", ips: [] });
  });
});
