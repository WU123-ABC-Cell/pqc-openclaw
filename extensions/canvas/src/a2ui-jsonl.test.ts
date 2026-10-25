import { describe, expect, it } from "vitest";
import { validateSupportedA2UIJsonl } from "./a2ui-jsonl.js";

const message = '{"deleteSurface":{"surfaceId":"main"}}';

describe("Canvas A2UI JSONL input bounds", () => {
  it("accepts ordinary v0.8 messages", () => {
    expect(validateSupportedA2UIJsonl(`${message}\n${message}`).messageCount).toBe(2);
  });

  it("rejects too many messages before forwarding to native nodes", () => {
    expect(() => validateSupportedA2UIJsonl(Array(1025).fill(message).join("\n"))).toThrow(
      /too many messages/,
    );
  });

  it("rejects oversized UTF-8 input before splitting or JSON parsing", () => {
    expect(() => validateSupportedA2UIJsonl(`${message}\n${"汉".repeat(6_000_000)}`)).toThrow(
      /payload exceeds 16 MiB/,
    );
  });
});
