// Bound untrusted A2UI objects before the bundled v0.8 parser walks them.
const MAX_MESSAGES = 1024;
const MAX_ARRAY_MEMBERS = 4096;
const MAX_NODES = 16384;
const MAX_DEPTH = 32;
const MAX_STRING_BYTES = 16 * 1024 * 1024;

export function assertA2UIMessageLimits(messages: unknown): asserts messages is unknown[] {
  if (!Array.isArray(messages)) {
    throw new Error("A2UI: expected messages array");
  }
  if (messages.length > MAX_MESSAGES) {
    throw new Error("A2UI: too many messages");
  }

  const encoder = new TextEncoder();
  const seen = new WeakSet();
  const pending: Array<{ value: unknown; depth: number }> = [{ value: messages, depth: 0 }];
  let nodes = 0;
  let discovered = 1;
  let arrayMembers = 0;
  let stringBytes = 0;
  const countString = (value: string) => {
    if (value.length > MAX_STRING_BYTES) {
      throw new Error("A2UI: message text exceeds limit");
    }
    stringBytes += encoder.encode(value).length;
    if (stringBytes > MAX_STRING_BYTES) {
      throw new Error("A2UI: message text exceeds limit");
    }
  };

  while (pending.length > 0) {
    const entry = pending.pop();
    if (!entry) {
      break;
    }
    const { value, depth } = entry;
    if (++nodes > MAX_NODES || depth > MAX_DEPTH) {
      throw new Error("A2UI: message structure exceeds limit");
    }
    if (typeof value === "string") {
      countString(value);
    } else if (value && typeof value === "object") {
      if (seen.has(value)) {
        throw new Error("A2UI: repeated message object");
      }
      seen.add(value);
      if (Array.isArray(value)) {
        arrayMembers += value.length;
        if (arrayMembers > MAX_ARRAY_MEMBERS) {
          throw new Error("A2UI: too many array members");
        }
        discovered += value.length;
        if (discovered > MAX_NODES) {
          throw new Error("A2UI: message structure exceeds limit");
        }
        for (const member of value) {
          pending.push({ value: member, depth: depth + 1 });
        }
      } else {
        for (const key in value) {
          if (Object.hasOwn(value, key)) {
            if (++discovered > MAX_NODES) {
              throw new Error("A2UI: message structure exceeds limit");
            }
            countString(key);
            pending.push({ value: (value as Record<string, unknown>)[key], depth: depth + 1 });
          }
        }
      }
    }
  }
}
