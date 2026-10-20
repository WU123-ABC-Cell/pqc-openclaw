import { SimplePool, finalizeEvent, nip44, type Event } from "nostr-tools";
import { createDirectDmPreCryptoGuardPolicy } from "openclaw/plugin-sdk/direct-dm-guard-policy";
import { openClawPqcDm } from "openclaw/plugin-sdk/security-runtime";
import type { NostrMetrics } from "./metrics.js";
import type { CircuitBreaker, RelayHealthTracker } from "./nostr-relay-health.js";
import { publishNostrEventToRelay } from "./relay-publish.js";

const { decodeMlKem768PublicKey, encryptOpenClawPqcDmV1, OPENCLAW_PQC_DM_EVENT_KIND } =
  openClawPqcDm;
const PAIRING_ML_KEM_KEY_TAG = "ocpqc-pk";

// Send DM with Circuit Breaker + Health Scoring

export function decodeSignedPairingPublicKey(event: Event): Uint8Array {
  const keyTags = event.tags.filter((tag) => tag[0] === PAIRING_ML_KEM_KEY_TAG);
  const encodedKey = keyTags[0]?.[1];
  if (keyTags.length !== 1 || keyTags[0]?.length !== 2 || typeof encodedKey !== "string") {
    throw new Error("Nostr pairing requires exactly one signed ML-KEM public key tag");
  }
  return decodeMlKem768PublicKey(encodedKey);
}

/**
 * Send an encrypted DM to a pubkey
 */
export async function sendEncryptedDm(
  pool: SimplePool,
  sk: Uint8Array,
  fromPubkey: string,
  senderMlKemPublicKey: string,
  peerMlKemPublicKeys: ReadonlyMap<string, Uint8Array>,
  toPubkey: string,
  text: string,
  relays: string[],
  metrics: NostrMetrics,
  circuitBreakers: Map<string, CircuitBreaker>,
  healthTracker: RelayHealthTracker,
  sizeLimits: Pick<
    ReturnType<typeof createDirectDmPreCryptoGuardPolicy>,
    "maxPlaintextBytes" | "maxCiphertextBytes"
  >,
  onError?: (error: Error, context: string) => void,
  replyToEventId?: string,
  pairingRecipientKey?: Uint8Array,
): Promise<string> {
  const recipientMlKemPublicKey = peerMlKemPublicKeys.get(toPubkey) ?? pairingRecipientKey;
  if (!recipientMlKemPublicKey) {
    throw new Error(`No pinned ML-KEM-768 public key for Nostr peer ${toPubkey}`);
  }
  const plaintextBytes = Buffer.byteLength(text, "utf8");
  if (plaintextBytes > sizeLimits.maxPlaintextBytes) {
    throw new Error(
      `Nostr plaintext is ${plaintextBytes} bytes, exceeding the ${sizeLimits.maxPlaintextBytes}-byte receive limit`,
    );
  }
  const classicalConversationKey = nip44.v2.utils.getConversationKey(sk, toPubkey);
  let ciphertext: string;
  try {
    ciphertext = encryptOpenClawPqcDmV1({
      classicalConversationKey,
      recipientMlKemPublicKey,
      senderPubkey: fromPubkey,
      recipientPubkey: toPubkey,
      plaintext: text,
    });
  } finally {
    classicalConversationKey.fill(0);
  }
  const ciphertextBytes = Buffer.byteLength(ciphertext, "utf8");
  if (ciphertextBytes > sizeLimits.maxCiphertextBytes) {
    throw new Error(
      `Nostr ciphertext is ${ciphertextBytes} bytes, exceeding the ${sizeLimits.maxCiphertextBytes}-byte receive limit`,
    );
  }
  const tags = [
    ["p", toPubkey],
    [PAIRING_ML_KEM_KEY_TAG, senderMlKemPublicKey],
  ];
  if (replyToEventId) {
    tags.push(["e", replyToEventId]);
  }
  const reply = finalizeEvent(
    {
      kind: OPENCLAW_PQC_DM_EVENT_KIND,
      content: ciphertext,
      tags,
      created_at: Math.floor(Date.now() / 1000),
    },
    sk,
  );

  // Sort relays by health score (best first)
  const sortedRelays = healthTracker.getSortedRelays(relays);

  // Try relays in order of health, respecting circuit breakers
  let lastError: Error | undefined;
  for (const relay of sortedRelays) {
    const cb = circuitBreakers.get(relay);

    // Skip if circuit breaker is open
    if (cb && !cb.canAttempt()) {
      continue;
    }

    const startTime = Date.now();
    try {
      await publishNostrEventToRelay(pool, relay, reply);
      const latency = Date.now() - startTime;

      // Record success
      cb?.recordSuccess();
      healthTracker.recordSuccess(relay, latency);

      return reply.id;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      const latency = Date.now() - startTime;

      // Record failure
      cb?.recordFailure();
      healthTracker.recordFailure(relay);
      metrics.emit("relay.error", 1, { relay, latency });

      onError?.(lastError, `publish to ${relay}`);
    }
  }

  throw new Error(`Failed to publish to any relay: ${lastError?.message}`);
}
