import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { WebSocketServer } from "ws";
import type { Model } from "../types.js";
import {
  closeOpenAICodexWebSocketSessions,
  streamOpenAICodexResponses,
} from "./openai-chatgpt-responses.js";

// No constructor substitution: malformed upgrades must reach the actual Node
// transport, where native WebSocket used to throw outside the stream's catch.
describe("ChatGPT Responses Node handshake", () => {
  it("preserves an embedding application's legacy dispatcher policy", () => {
    const providerUrl = new URL("./openai-chatgpt-responses.ts", import.meta.url).href;
    // A fresh process is required: importing Undici 8 elsewhere can already
    // initialize its dispatcher bridge and hide a standalone-package regression.
    const output = execFileSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "--input-type=module",
        "--eval",
        `
          let calls = 0;
          const policy = {
            dispatch(_options, handler) {
              calls += 1;
              queueMicrotask(() => handler.onError(new Error("test policy rejected connection")));
              return true;
            },
          };
          const legacy = Symbol.for("undici.globalDispatcher.1");
          globalThis[legacy] = policy;
          const { streamOpenAICodexResponses } = await import(${JSON.stringify(providerUrl)});
          const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");
          const apiKey = encode({alg:"none"}) + "." + encode({
            "https://api.openai.com/auth": {chatgpt_account_id:"policy-test"},
          }) + ".test";
          const result = await streamOpenAICodexResponses({
            id:"gpt-5.6-luna", name:"test", api:"openai-chatgpt-responses", provider:"openai",
            baseUrl:"http://127.0.0.1:38567", reasoning:true, input:["text"],
            cost:{input:0,output:0,cacheRead:0,cacheWrite:0}, contextWindow:128000,maxTokens:100,
          }, {messages:[{role:"user",content:"hello",timestamp:1}]},
          {apiKey,transport:"websocket",timeoutMs:3000}).result();
          console.log(JSON.stringify({
            preserved:globalThis[legacy] === policy, calls, stopReason:result.stopReason,
          }));
        `,
      ],
      { encoding: "utf8", timeout: 15000 },
    );
    expect(JSON.parse(output.trim())).toEqual({ preserved: true, calls: 1, stopReason: "error" });
  });

  it.each([
    { protocol: undefined, transport: "websocket", expected: "stop", sse: 0 },
    { protocol: "unsolicited", transport: "websocket", expected: "error", sse: 0 },
    { protocol: "one, two", transport: "websocket", expected: "error", sse: 0 },
    { protocol: "unsolicited", transport: "auto", expected: "stop", sse: 1 },
  ] as const)(
    "handles $protocol with $transport",
    async ({ protocol, transport, expected, sse }) => {
      const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
      const apiKey = `${encode({ alg: "none", typ: "JWT" })}.${encode({
        "https://api.openai.com/auth": { chatgpt_account_id: "handshake-test" },
      })}.test`;
      const completion = {
        type: "response.completed",
        response: {
          id: "resp_handshake",
          status: "completed",
          output: [],
          usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
        },
      };
      let sseRequests = 0;
      let authorization: string | undefined;
      let accountId: string | string[] | undefined;
      let messages = 0;
      const server = createServer((_request, response) => {
        sseRequests += 1;
        response.writeHead(200, { "content-type": "text/event-stream" });
        response.end(`data: ${JSON.stringify(completion)}\n\n`);
      });
      const sockets = new WebSocketServer({ server });
      sockets.on("headers", (headers) => {
        if (protocol !== undefined) {
          headers.push(`Sec-WebSocket-Protocol: ${protocol}`);
        }
      });
      sockets.on("connection", (socket, request) => {
        authorization = request.headers.authorization;
        accountId = request.headers["chatgpt-account-id"];
        socket.on("message", () => {
          messages += 1;
          socket.send(JSON.stringify(completion));
        });
      });
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      const model = {
        id: "gpt-5.6-luna",
        name: "handshake",
        api: "openai-chatgpt-responses",
        provider: "openai",
        baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}/backend-api`,
        reasoning: true,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 128000,
        maxTokens: 100,
      } satisfies Model<"openai-chatgpt-responses">;
      try {
        const result = await streamOpenAICodexResponses(
          model,
          { messages: [{ role: "user", content: "hello", timestamp: 1 }] },
          { apiKey, transport, timeoutMs: 3000 },
        ).result();
        expect(result.stopReason).toBe(expected);
        expect(sseRequests).toBe(sse);
        expect(messages).toBe(protocol === undefined ? 1 : 0);
        expect(authorization).toBe(`Bearer ${apiKey}`);
        expect(accountId).toBe("handshake-test");
      } finally {
        closeOpenAICodexWebSocketSessions();
        for (const socket of sockets.clients) {
          socket.terminate();
        }
        await new Promise<void>((resolve) => {
          sockets.close(() => resolve());
        });
        server.closeAllConnections();
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
        });
      }
    },
  );
});
