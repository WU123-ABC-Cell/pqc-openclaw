import { createDirectDmPreCryptoGuardPolicy } from "openclaw/plugin-sdk/direct-dm-guard-policy";
import { chunkTextForOutbound } from "openclaw/plugin-sdk/text-chunking";

// The same default policy guards the receiver before and after decryption.
export const DEFAULT_NOSTR_DM_SIZE_LIMITS = createDirectDmPreCryptoGuardPolicy();
export const NOSTR_OUTBOUND_TEXT_CHUNK_LIMIT = 4_000;

function splitByUtf8Bytes(text: string, maxBytes: number): string[] {
  const chunks: string[] = [];
  let chunk = "";
  let chunkBytes = 0;
  for (const scalar of text) {
    const scalarBytes = Buffer.byteLength(scalar, "utf8");
    if (scalarBytes > maxBytes) {
      throw new Error(`Nostr plaintext byte limit ${maxBytes} cannot fit a Unicode character`);
    }
    if (chunk && chunkBytes + scalarBytes > maxBytes) {
      chunks.push(chunk);
      chunk = "";
      chunkBytes = 0;
    }
    chunk += scalar;
    chunkBytes += scalarBytes;
  }
  if (chunk) {
    chunks.push(chunk);
  }
  return chunks;
}

/** Preserve the existing readable character splits, then enforce the wire byte budget. */
export function chunkNostrOutboundText(
  text: string,
  characterLimit = NOSTR_OUTBOUND_TEXT_CHUNK_LIMIT,
): string[] {
  return chunkTextForOutbound(text, characterLimit).flatMap((chunk) =>
    splitByUtf8Bytes(chunk, DEFAULT_NOSTR_DM_SIZE_LIMITS.maxPlaintextBytes),
  );
}
