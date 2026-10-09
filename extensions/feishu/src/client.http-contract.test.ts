import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Readable } from "node:stream";
import * as Lark from "@larksuiteoapi/node-sdk";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createFeishuClient, getFeishuUserAgent, resetFeishuProxyAgentForTest } from "./client.js";

type Payload = { code: number; data: { message_id: string } };
type ReceivedRequest = {
  method: string | undefined;
  url: string | undefined;
  body: string;
  authorization: string | undefined;
  userAgent: string | undefined;
};

const payload: Payload = { code: 0, data: { message_id: "local-message" } };
const proxyEnvKeys = [
  "https_proxy",
  "HTTPS_PROXY",
  "http_proxy",
  "HTTP_PROXY",
  "all_proxy",
  "ALL_PROXY",
  "OPENCLAW_PROXY_ACTIVE",
  "OPENCLAW_FEISHU_HTTP_TIMEOUT_MS",
] as const;

describe("Feishu SDK HTTP response contract (real loopback transport)", () => {
  let server: Server;
  let client: Lark.Client;
  let http: Lark.HttpInstance;
  let origin: string;
  const received: ReceivedRequest[] = [];

  beforeAll(async () => {
    for (const key of proxyEnvKeys) {
      vi.stubEnv(key, undefined);
    }
    resetFeishuProxyAgentForTest();
    server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      received.push({
        method: req.method,
        url: req.url,
        body: Buffer.concat(chunks).toString("utf8"),
        authorization: req.headers.authorization,
        userAgent: req.headers["user-agent"],
      });
      res.setHeader("x-contract", "loopback");
      if (req.url === "/timeout") {
        return; // Deliberately leave the response pending until Axios aborts.
      }
      if (req.url === "/text") {
        res.setHeader("content-type", "text/plain");
        res.end("原样返回");
        return;
      }
      if (req.url === "/bytes") {
        res.setHeader("content-type", "application/octet-stream");
        res.end(Buffer.from([0, 1, 255]));
        return;
      }
      res.setHeader("content-type", "application/json");
      if (req.url === "/open-apis/auth/v3/tenant_access_token/internal") {
        res.end(
          JSON.stringify({ code: 0, tenant_access_token: "local-bootstrap-token", expire: 7200 }),
        );
        return;
      }
      if (req.url === "/error") {
        res.statusCode = 503;
        res.end(JSON.stringify({ code: 503, msg: "local rejection" }));
        return;
      }
      res.end(JSON.stringify(payload));
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    client = createFeishuClient({
      accountId: "http-contract-loopback",
      appId: "cli_0123456789abcdef",
      appSecret: "local-fixture-secret", // pragma: allowlist secret
      domain: origin,
    });
    http = client.httpInstance;
  });

  beforeEach(() => {
    received.length = 0;
  });

  afterAll(async () => {
    resetFeishuProxyAgentForTest();
    vi.unstubAllEnvs();
    if (server) {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });

  const calls: Array<{
    method: string;
    call: (transport: Lark.HttpInstance, url: string) => Promise<Payload | string>;
    body?: { value: string };
  }> = [
    {
      method: "REQUEST",
      call: (transport, url) => transport.request<unknown, Payload>({ url, method: "GET" }),
    },
    { method: "GET", call: (transport, url) => transport.get<unknown, Payload>(url) },
    {
      method: "POST",
      call: (transport, url) => transport.post<unknown, Payload>(url, { value: "post" }),
      body: { value: "post" },
    },
    {
      method: "PUT",
      call: (transport, url) => transport.put<unknown, Payload>(url, { value: "put" }),
      body: { value: "put" },
    },
    {
      method: "PATCH",
      call: (transport, url) => transport.patch<unknown, Payload>(url, { value: "patch" }),
      body: { value: "patch" },
    },
    { method: "DELETE", call: (transport, url) => transport.delete<unknown, Payload>(url) },
    { method: "HEAD", call: (transport, url) => transport.head<unknown, string>(url) },
    { method: "OPTIONS", call: (transport, url) => transport.options<unknown, Payload>(url) },
  ];

  it.each(calls)(
    "preserves the $method payload and request options",
    async ({ method, call, body }) => {
      // Official SDK origins must be rewritten to this account's loopback transport.
      const result = await call(http, "https://open.feishu.cn/contract");
      expect(result).toEqual(method === "HEAD" ? "" : payload);
      expect(received).toHaveLength(1);
      expect(received[0]).toMatchObject({
        method: method === "REQUEST" ? "GET" : method,
        url: "/contract",
        userAgent: getFeishuUserAgent(),
      });
      expect(received[0]?.body).toBe(body ? JSON.stringify(body) : "");
    },
  );

  it("preserves the SDK's explicit response-with-headers mode", async () => {
    const result = await http.get<unknown, { data: Payload; headers: Record<string, string> }>(
      `${origin}/contract`,
      { $return_headers: true },
    );
    expect(result.data).toEqual(payload);
    expect(result.headers["x-contract"]).toBe("loopback");
    expect(result).not.toHaveProperty("status");
  });

  it("preserves text and arraybuffer payloads", async () => {
    expect(await http.get<unknown, string>(`${origin}/text`, { responseType: "text" })).toBe(
      "原样返回",
    );
    const bytes = await http.get<unknown, Buffer>(`${origin}/bytes`, {
      responseType: "arraybuffer",
    });
    expect(Buffer.isBuffer(bytes)).toBe(true);
    expect(bytes).toEqual(Buffer.from([0, 1, 255]));
  });

  it("preserves stream payloads with headers used by SDK downloads", async () => {
    const result = await http.get<unknown, { data: Readable; headers: Record<string, string> }>(
      `${origin}/bytes`,
      { responseType: "stream", $return_headers: true },
    );
    const chunks: Buffer[] = [];
    for await (const chunk of result.data) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    expect(Buffer.concat(chunks)).toEqual(Buffer.from([0, 1, 255]));
    expect(result.headers["x-contract"]).toBe("loopback");
  });

  it("does not convert HTTP failures to successful payloads", async () => {
    await expect(http.get(`${origin}/error`)).rejects.toMatchObject({
      isAxiosError: true,
      response: { status: 503, data: { code: 503, msg: "local rejection" } },
    });
  });

  it("preserves caller timeouts and rejection without a response", async () => {
    await expect(http.get(`${origin}/timeout`, { timeout: 30 })).rejects.toMatchObject({
      isAxiosError: true,
      code: "ECONNABORTED",
    });
  });

  it("returns the actual SDK Client.request business envelope", async () => {
    const result = await client.request<Payload>({ method: "GET", url: "/contract" });
    expect(result).toEqual(payload);
    expect(received[0]).toMatchObject({
      method: "POST",
      url: "/open-apis/auth/v3/tenant_access_token/internal",
    });
    expect(JSON.parse(received[0]?.body ?? "")).toEqual({
      app_id: "cli_0123456789abcdef",
      app_secret: "local-fixture-secret", // pragma: allowlist secret
    });
    expect(received[1]).toMatchObject({
      method: "GET",
      url: "/contract",
      authorization: "Bearer local-bootstrap-token",
    });
  });

  it("returns the generated message API envelope without double unwrapping", async () => {
    const body = { receive_id: "local-chat", msg_type: "text", content: '{"text":"本地消息"}' };
    const result = await client.im.message.create(
      { params: { receive_id_type: "chat_id" }, data: body },
      Lark.withUserAccessToken("local-fixture-token"),
    );
    expect(result).toEqual(payload);
    expect(received[0]).toMatchObject({
      method: "POST",
      url: "/open-apis/im/v1/messages?receive_id_type=chat_id",
      body: JSON.stringify(body),
      authorization: "Bearer local-fixture-token",
    });
  });
});
