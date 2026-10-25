import { describe, expect, it } from "vitest";
import { assertA2UIMessageLimits } from "./message-limits.js";

const textSurface = [
  {
    surfaceUpdate: {
      surfaceId: "main",
      components: [
        { id: "root", component: { Column: { children: { explicitList: ["text"] } } } },
        { id: "text", component: { Text: { text: { literalString: "你好" } } } },
      ],
    },
  },
  { beginRendering: { surfaceId: "main", root: "root" } },
];

describe("Canvas A2UI preparse limits", () => {
  it("accepts an ordinary two-message surface before the parser", () => {
    expect(() => assertA2UIMessageLimits(textSurface)).not.toThrow();
    expect(() =>
      assertA2UIMessageLimits([
        { dataModelUpdate: { surfaceId: "main", contents: Array(4095).fill(null) } },
      ]),
    ).not.toThrow();
  });

  it("rejects oversized top-level and nested arrays before parsing", () => {
    expect(() => assertA2UIMessageLimits(Array(1025).fill(null))).toThrow(/too many messages/);
    expect(() =>
      assertA2UIMessageLimits([
        { dataModelUpdate: { surfaceId: "main", contents: Array(4096).fill(null) } },
      ]),
    ).toThrow(/too many array members/);
    expect(() =>
      assertA2UIMessageLimits([
        {
          surfaceUpdate: {
            surfaceId: "main",
            components: [
              {
                component: {
                  Column: { children: { explicitList: Array(4096).fill("x") } },
                },
              },
            ],
          },
        },
      ]),
    ).toThrow(/too many array members/);
  });

  it("enforces UTF-8 bytes and nesting without recursively walking the parser", () => {
    expect(() => assertA2UIMessageLimits([{ text: "汉".repeat(6_000_000) }])).toThrow(
      /message text exceeds limit/,
    );
    let nested: unknown = "x";
    for (let i = 0; i < 34; i++) {
      nested = { valueMap: [nested] };
    }
    expect(() => assertA2UIMessageLimits([nested])).toThrow(/message structure exceeds limit/);
  });

  it("rejects repeated object references from direct browser API callers", () => {
    const shared = { deleteSurface: { surfaceId: "main" } };
    expect(() => assertA2UIMessageLimits([shared, shared])).toThrow(/repeated message object/);
  });
});
