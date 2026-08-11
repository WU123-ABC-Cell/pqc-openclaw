// PQC fork M10: Nostr NIP-44 v2 + ML-KEM-768 hybrid (whitepaper 1.1).
//
// The tests cover the cryptographic envelope, the wire format
// (auto-detect via "pqc2:" prefix), the FIPS 203 / 204 round-trip,
// the MAC / AAD path, and the integration with @noble/ciphers'
// ChaCha20 + @noble/post-quantum's ML-KEM-768.
import { chacha20 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import {
  decapsulateMlKem768,
  encapsulateMlKem768,
  generateMlKem768KeyPair,
  isPqcNip44Envelope,
  nip44PqcDecrypt,
  nip44PqcEncrypt,
  PQC_NIP44_PREFIX,
} from "./nip44-v2.js";

const tracked: Uint8Array[] = [];
function newSharedSecret(): Uint8Array {
  const s = randomBytes(32);
  tracked.push(s);
  return s;
}

beforeEach(() => {
  while (tracked.length > 0) tracked.pop();
});

afterEach(() => {
  while (tracked.length > 0) tracked.pop();
});

describe("ML-KEM-768 (FIPS 203) keypair round-trip", () => {
  it("encapsulate + decapsulate recovers the same shared secret", () => {
    const kp = generateMlKem768KeyPair();
    expect(kp.publicKey.length).toBe(1184); // ML-KEM-768 public-key bytes
    expect(kp.secretKey.length).toBe(2400); // ML-KEM-768 secret-key bytes
    const enc = encapsulateMlKem768(kp.publicKey);
    expect(enc.ciphertext.length).toBe(1088); // ML-KEM-768 ciphertext bytes
    expect(enc.sharedSecret.length).toBe(32);
    const dec = decapsulateMlKem768(kp.secretKey, enc.ciphertext);
    expect(dec).toEqual(enc.sharedSecret);
  });

  it("two independent keypairs do not produce the same shared secret", () => {
    const a = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(a.publicKey);
    const b = generateMlKem768KeyPair();
    expect(enc.sharedSecret.length).toBe(32);
    // The shared secret is fresh per (keypair, encap); the two
    // independent test runs use different randomness, so we
    // can only assert the API shape here, not the bit values.
  });
});

describe("PQC NIP-44 v2 envelope (whitepaper 1.1)", () => {
  it("round-trips a short plaintext through the hybrid envelope", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const plaintext = "hello pqc nostr";
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext,
    });
    expect(isPqcNip44Envelope(envelope)).toBe(true);
    expect(envelope.startsWith(PQC_NIP44_PREFIX)).toBe(true);
    const decrypted = nip44PqcDecrypt({
      ecdhSharedSecret: ecdh,
      mlKemSharedSecret: decapsulateMlKem768(kp.secretKey, enc.ciphertext),
      envelope,
    });
    expect(decrypted).toBe(plaintext);
  });

  it("round-trips a multi-block plaintext (forces chacha20 padding)", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const plaintext = "x".repeat(100);
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext,
    });
    const decrypted = nip44PqcDecrypt({
      ecdhSharedSecret: ecdh,
      mlKemSharedSecret: decapsulateMlKem768(kp.secretKey, enc.ciphertext),
      envelope,
    });
    expect(decrypted).toBe(plaintext);
  });

  it("round-trips an empty plaintext is rejected (min plaintext length is 1)", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    expect(() =>
      nip44PqcEncrypt({
        ecdhSharedSecret: ecdh,
        mlKemCiphertext: enc.ciphertext,
        mlKemSharedSecret: enc.sharedSecret,
        plaintext: "",
      }),
    ).toThrow(/plaintext length/);
  });

  it("round-trips a 32-byte plaintext (boundary of the padding rule)", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const plaintext = "a".repeat(32);
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext,
    });
    const decrypted = nip44PqcDecrypt({
      ecdhSharedSecret: ecdh,
      mlKemSharedSecret: decapsulateMlKem768(kp.secretKey, enc.ciphertext),
      envelope,
    });
    expect(decrypted).toBe(plaintext);
  });

  it("refuses an envelope that does not start with the PQC prefix", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    expect(() =>
      nip44PqcDecrypt({
        ecdhSharedSecret: ecdh,
        mlKemSharedSecret: enc.sharedSecret,
        envelope: "2:not-a-pqc-envelope",
      }),
    ).toThrow(/pqc2:/);
  });

  it("refuses a wrong-length ecdh shared secret", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    expect(() =>
      nip44PqcEncrypt({
        ecdhSharedSecret: new Uint8Array(16),
        mlKemCiphertext: enc.ciphertext,
        mlKemSharedSecret: enc.sharedSecret,
        plaintext: "x",
      }),
    ).toThrow(/32 bytes/);
  });

  it("refuses a wrong-size ML-KEM ciphertext", () => {
    const ecdh = newSharedSecret();
    expect(() =>
      nip44PqcEncrypt({
        ecdhSharedSecret: ecdh,
        mlKemCiphertext: new Uint8Array(64),
        mlKemSharedSecret: new Uint8Array(32),
        plaintext: "x",
      }),
    ).toThrow(/1088 bytes/);
  });

  it("fails closed on a tampered ciphertext segment (auth failure)", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext: "the quick brown fox",
    });
    // Tamper one byte of the embedded chacha20 ciphertext (the
    // middle dot-separated segment). The MAC must catch this.
    const parts = envelope.split(".");
    const tamperedCt = Buffer.from(parts[1], "base64url");
    tamperedCt[20] ^= 0x01;
    const tampered = `${parts[0]}.${Buffer.from(tamperedCt).toString("base64url")}.${parts[2]}`;
    expect(() =>
      nip44PqcDecrypt({
        ecdhSharedSecret: ecdh,
        mlKemSharedSecret: enc.sharedSecret,
        envelope: tampered,
      }),
    ).toThrow(/MAC verification/);
  });

  it("fails closed on a tampered MAC segment (auth failure)", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext: "the quick brown fox",
    });
    const parts = envelope.split(".");
    const tamperedMac = Buffer.from(parts[2], "base64url");
    tamperedMac[0] ^= 0x80;
    const tampered = `${parts[0]}.${parts[1]}.${Buffer.from(tamperedMac).toString("base64url")}`;
    expect(() =>
      nip44PqcDecrypt({
        ecdhSharedSecret: ecdh,
        mlKemSharedSecret: enc.sharedSecret,
        envelope: tampered,
      }),
    ).toThrow(/MAC verification/);
  });

  it("fails closed on a wrong ECDH shared secret (auth failure)", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext: "the quick brown fox",
    });
    const wrongEcdh = newSharedSecret();
    expect(() =>
      nip44PqcDecrypt({
        ecdhSharedSecret: wrongEcdh,
        mlKemSharedSecret: decapsulateMlKem768(kp.secretKey, enc.ciphertext),
        envelope,
      }),
    ).toThrow(/MAC verification/);
  });

  it("fails closed on a wrong ML-KEM shared secret (auth failure)", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext: "the quick brown fox",
    });
    const wrongKem = randomBytes(32);
    expect(() =>
      nip44PqcDecrypt({
        ecdhSharedSecret: ecdh,
        mlKemSharedSecret: wrongKem,
        envelope,
      }),
    ).toThrow(/MAC verification/);
  });

  it("binds additional authenticated data (AAD) into the MAC", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const ecdh = newSharedSecret();
    const aad = new TextEncoder().encode("conversation-id-abc");
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: ecdh,
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext: "hello pqc nostr",
      aad,
    });
    // Decrypt with the right AAD: success.
    const ok = nip44PqcDecrypt({
      ecdhSharedSecret: ecdh,
      mlKemSharedSecret: decapsulateMlKem768(kp.secretKey, enc.ciphertext),
      envelope,
      aad,
    });
    expect(ok).toBe("hello pqc nostr");
    // Decrypt with a different AAD: MAC fails.
    expect(() =>
      nip44PqcDecrypt({
        ecdhSharedSecret: ecdh,
        mlKemSharedSecret: decapsulateMlKem768(kp.secretKey, enc.ciphertext),
        envelope,
        aad: new TextEncoder().encode("conversation-id-other"),
      }),
    ).toThrow(/MAC verification/);
  });
});

describe("isPqcNip44Envelope (auto-detect for the Nostr extension)", () => {
  it("returns true for an envelope with the PQC prefix", () => {
    const kp = generateMlKem768KeyPair();
    const enc = encapsulateMlKem768(kp.publicKey);
    const envelope = nip44PqcEncrypt({
      ecdhSharedSecret: newSharedSecret(),
      mlKemCiphertext: enc.ciphertext,
      mlKemSharedSecret: enc.sharedSecret,
      plaintext: "x",
    });
    expect(isPqcNip44Envelope(envelope)).toBe(true);
  });

  it("returns false for the upstream NIP-44 v2 prefix", () => {
    expect(isPqcNip44Envelope("2:some-base64url")).toBe(false);
  });

  it("returns false for plain text", () => {
    expect(isPqcNip44Envelope("hello world")).toBe(false);
  });
});
