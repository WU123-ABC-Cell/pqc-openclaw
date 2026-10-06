import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { JsonSchemaType } from "@modelcontextprotocol/sdk/validation/types.js";
import { describe, expect, it } from "vitest";
import { createMcpJsonSchemaValidator } from "./mcp-json-schema-validator.js";

async function withCatalog(
  outputSchema: JsonSchemaType & { type: "object" },
  run: (client: Client) => Promise<void>,
) {
  const server = new Server(
    { name: "schema-fixture", version: "1" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "echo", inputSchema: { type: "object" }, outputSchema }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async ({ params }) => ({
    content: [],
    structuredContent: params.arguments ?? {},
  }));
  const client = new Client(
    { name: "schema-test", version: "1" },
    { jsonSchemaValidator: createMcpJsonSchemaValidator() },
  );
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await run(client);
  } finally {
    await client.close();
    await server.close();
  }
}

describe("MCP draft-07 URI resolution through the real SDK", () => {
  it.each([
    ["http://[::not-valid]/schema", /URI host is malformed/],
    ["http://[1::2::3]/schema", /URI host is malformed/],
    ["%2f%2fevil.example:/schema", /URI scheme is malformed/],
  ])("rejects malformed schema bases during tools/list: %s", async ($id, error) => {
    await withCatalog(
      {
        $schema: "http://json-schema.org/draft-07/schema#",
        $id,
        type: "object",
        definitions: { value: { type: "string" } },
        properties: { value: { $ref: "#/definitions/value" } },
      },
      async (client) => {
        await expect(client.listTools()).rejects.toThrow(error);
      },
    );
  });

  it.each([
    ["https://example.test/schemas/root", "value", "value"],
    ["https://例子.test/schemas/root", "value", "value"],
    ["https://example.test/schemas/root", "#value", "#value"],
    ["https://example.test/schemas/root", "#value", "#%76alue"],
  ])("preserves references and output validation: %s %s %s", async ($id, childId, $ref) => {
    await withCatalog(
      {
        $schema: "http://json-schema.org/draft-07/schema#",
        $id,
        type: "object",
        definitions: { value: { $id: childId, type: "string" } },
        properties: { value: { $ref } },
        required: ["value"],
        additionalProperties: false,
      },
      async (client) => {
        expect((await client.listTools()).tools).toHaveLength(1);
        const result = await client.callTool({ name: "echo", arguments: { value: "正常" } });
        expect(result.structuredContent).toEqual({ value: "正常" });
        await expect(client.callTool({ name: "echo", arguments: { value: 42 } })).rejects.toThrow();
      },
    );
  });
});
