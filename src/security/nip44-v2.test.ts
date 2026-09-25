import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import {
  decryptOpenClawPqcDmV1,
  deriveMlKem768PublicKey,
  encodeMlKemKey,
  encryptOpenClawPqcDmV1,
  generateMlKem768KeyPair,
  isOpenClawPqcDmEnvelope,
  ML_KEM_768_CIPHERTEXT_BYTES,
  ML_KEM_768_PUBLIC_KEY_BYTES,
  ML_KEM_768_SECRET_KEY_BYTES,
  OPENCLAW_PQC_DM_PREFIX,
} from "./nip44-v2.js";

const ALICE = "ab".repeat(32);
const BOB = "22".repeat(32);

describe("OpenClaw PQC DM v1", () => {
  let recipient: ReturnType<typeof generateMlKem768KeyPair>;
  let otherRecipient: ReturnType<typeof generateMlKem768KeyPair>;
  let classicalConversationKey: Uint8Array;

  beforeAll(() => {
    recipient = generateMlKem768KeyPair();
    otherRecipient = generateMlKem768KeyPair();
    classicalConversationKey = new Uint8Array(randomBytes(32));
  });

  function encrypt(plaintext = "hello pqc nostr"): string {
    return encryptOpenClawPqcDmV1({
      classicalConversationKey,
      recipientMlKemPublicKey: recipient.publicKey,
      senderPubkey: ALICE,
      recipientPubkey: BOB,
      plaintext,
    });
  }

  function decrypt(envelope: string): string {
    return decryptOpenClawPqcDmV1({
      classicalConversationKey,
      recipientMlKemSecretKey: recipient.secretKey,
      senderPubkey: ALICE,
      recipientPubkey: BOB,
      envelope,
    });
  }

  function mutateRaw(envelope: string, offset: number): string {
    const raw = Buffer.from(envelope.slice(OPENCLAW_PQC_DM_PREFIX.length), "base64url");
    raw[offset] ^= 1;
    return `${OPENCLAW_PQC_DM_PREFIX}${raw.toString("base64url")}`;
  }

  it("round-trips through internally encapsulated and decapsulated ML-KEM", () => {
    expect(decrypt(encrypt())).toBe("hello pqc nostr");
  });

  it("generates independent envelopes for repeated plaintext", () => {
    expect(encrypt("same")).not.toBe(encrypt("same"));
  });

  it("binds the exact embedded ML-KEM ciphertext", () => {
    const envelope = encrypt();
    expect(() => decrypt(mutateRaw(envelope, 1 + 32))).toThrow(/authentication failed/u);
  });

  it.each([
    ["nonce", 1],
    ["ciphertext", 1 + 32 + ML_KEM_768_CIPHERTEXT_BYTES],
    ["mac", -1],
  ])("rejects a mutated %s", (_name, requestedOffset) => {
    const envelope = encrypt();
    const rawLength = Buffer.from(
      envelope.slice(OPENCLAW_PQC_DM_PREFIX.length),
      "base64url",
    ).length;
    const offset = requestedOffset < 0 ? rawLength + requestedOffset : requestedOffset;
    expect(() => decrypt(mutateRaw(envelope, offset))).toThrow(/authentication failed/u);
  });

  it("rejects an unsupported wire version before decryption", () => {
    expect(() => decrypt(mutateRaw(encrypt(), 0))).toThrow(/Unsupported/u);
  });

  it("binds sender and recipient Nostr identities", () => {
    const envelope = encrypt();
    expect(() =>
      decryptOpenClawPqcDmV1({
        classicalConversationKey,
        recipientMlKemSecretKey: recipient.secretKey,
        senderPubkey: BOB,
        recipientPubkey: ALICE,
        envelope,
      }),
    ).toThrow(/authentication failed/u);
  });

  it("rejects a different recipient ML-KEM secret key", () => {
    expect(() =>
      decryptOpenClawPqcDmV1({
        classicalConversationKey,
        recipientMlKemSecretKey: otherRecipient.secretKey,
        senderPubkey: ALICE,
        recipientPubkey: BOB,
        envelope: encrypt(),
      }),
    ).toThrow(/authentication failed/u);
  });

  it("uses the NIP-44 power-of-two padding buckets", () => {
    const envelope = encrypt("x".repeat(257));
    const raw = Buffer.from(envelope.slice(OPENCLAW_PQC_DM_PREFIX.length), "base64url");
    const expectedCiphertextBytes = 2 + 320;
    expect(raw.length).toBe(1 + 32 + ML_KEM_768_CIPHERTEXT_BYTES + expectedCiphertextBytes + 32);
    expect(decrypt(envelope)).toBe("x".repeat(257));
  });

  it("rejects non-canonical base64url envelopes", () => {
    expect(() => decrypt(`${encrypt()}=`)).toThrow(/canonical base64url/u);
  });

  it("validates Nostr identity encodings", () => {
    expect(() =>
      encryptOpenClawPqcDmV1({
        classicalConversationKey,
        recipientMlKemPublicKey: recipient.publicKey,
        senderPubkey: ALICE.toUpperCase(),
        recipientPubkey: BOB,
        plaintext: "x",
      }),
    ).toThrow(/lowercase/u);
  });

  it("rejects empty plaintext and oversized plaintext", () => {
    expect(() => encrypt("")).toThrow(/plaintext/u);
    expect(() => encrypt("x".repeat(0x10000))).toThrow(/plaintext/u);
  });

  it("round-trips key encodings and derives the matching public key", () => {
    expect(recipient.publicKey).toHaveLength(ML_KEM_768_PUBLIC_KEY_BYTES);
    expect(recipient.secretKey).toHaveLength(ML_KEM_768_SECRET_KEY_BYTES);
    expect(deriveMlKem768PublicKey(recipient.secretKey)).toEqual(recipient.publicKey);
    expect(encodeMlKemKey(recipient.publicKey)).not.toContain("=");
  });

  it("detects only the explicit OpenClaw PQC wire prefix", () => {
    expect(isOpenClawPqcDmEnvelope(encrypt())).toBe(true);
    expect(isOpenClawPqcDmEnvelope("2:not-openclaw-pqc")).toBe(false);
    expect(isOpenClawPqcDmEnvelope("pqc2:not-openclaw-pqc")).toBe(false);
  });
});
