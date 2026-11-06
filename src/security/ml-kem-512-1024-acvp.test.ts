// Public NIST ACVP-Server v1.1.0.43 FIPS203 samples at commit
// 975de31eb83d87039ec88934fdc47d8c312b892d. Fixed answers cover the
// dependency's deterministic ML-KEM interfaces, not OpenClaw's Nostr envelope
// or FIPS certification. The product currently uses ML-KEM-768, tested separately.
import fs from "node:fs";
import { ml_kem512, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { describe, expect, it } from "vitest";

type AcvpFixture = {
  source: {
    commit: string;
    tag: string;
    revision: string;
    keyGenVsId: number;
    encapDecapVsId: number;
  };
  parameterSet: string;
  keyGen: {
    tgId: number;
    tcId: number;
    dHex: string;
    zHex: string;
    publicKeyHex: string;
    secretKeyHex: string;
  };
  encapsulation: {
    tgId: number;
    tcId: number;
    publicKeyHex: string;
    messageHex: string;
    ciphertextHex: string;
    sharedSecretHex: string;
  };
  decapsulation: {
    tgId: number;
    tcId: number;
    secretKeyHex: string;
    ciphertextHex: string;
    sharedSecretHex: string;
  };
};

for (const variant of [
  {
    size: 512,
    kem: ml_kem512,
    publicBytes: 800,
    secretBytes: 1632,
    ciphertextBytes: 768,
    keyGenCase: 1,
    decapsulationGroup: 4,
    decapsulationCase: 76,
    group: 1,
  },
  {
    size: 1024,
    kem: ml_kem1024,
    publicBytes: 1568,
    secretBytes: 3168,
    ciphertextBytes: 1568,
    keyGenCase: 51,
    decapsulationGroup: 6,
    decapsulationCase: 96,
    group: 3,
  },
]) {
  const fixture = JSON.parse(
    fs.readFileSync(
      new URL(`./fixtures/ml-kem-${variant.size}-acvp-v1.1.0.43.json`, import.meta.url),
      "utf8",
    ),
  ) as AcvpFixture;

  describe(`NIST ACVP ML-KEM-${variant.size} sample known answers`, () => {
    it("derives the official public and secret keys from fixed d and z", () => {
      expect(fixture.source).toMatchObject({
        commit: "975de31eb83d87039ec88934fdc47d8c312b892d",
        tag: "v1.1.0.43",
        revision: "FIPS203",
        keyGenVsId: 42,
      });
      expect(fixture.parameterSet).toBe(`ML-KEM-${variant.size}`);
      expect(fixture.keyGen).toMatchObject({ tgId: variant.group, tcId: variant.keyGenCase });
      const d = Buffer.from(fixture.keyGen.dHex, "hex");
      const z = Buffer.from(fixture.keyGen.zHex, "hex");
      const expectedPublic = Buffer.from(fixture.keyGen.publicKeyHex, "hex");
      const expectedSecret = Buffer.from(fixture.keyGen.secretKeyHex, "hex");
      expect([d.length, z.length, expectedPublic.length, expectedSecret.length]).toEqual([
        32,
        32,
        variant.publicBytes,
        variant.secretBytes,
      ]);

      const generated = variant.kem.keygen(Buffer.concat([d, z]));
      expect(Buffer.compare(Buffer.from(generated.publicKey), expectedPublic)).toBe(0);
      expect(Buffer.compare(Buffer.from(generated.secretKey), expectedSecret)).toBe(0);
      expect(
        Buffer.compare(Buffer.from(variant.kem.getPublicKey(expectedSecret)), expectedPublic),
      ).toBe(0);
    });

    it("encapsulates the official fixed ciphertext and shared secret", () => {
      expect(fixture.source).toMatchObject({ encapDecapVsId: 42 });
      expect(fixture.encapsulation).toMatchObject({
        tgId: variant.group,
        tcId: variant.keyGenCase,
      });
      const publicKey = Buffer.from(fixture.encapsulation.publicKeyHex, "hex");
      const message = Buffer.from(fixture.encapsulation.messageHex, "hex");
      const expectedCiphertext = Buffer.from(fixture.encapsulation.ciphertextHex, "hex");
      const expectedSharedSecret = Buffer.from(fixture.encapsulation.sharedSecretHex, "hex");
      expect([
        publicKey.length,
        message.length,
        expectedCiphertext.length,
        expectedSharedSecret.length,
      ]).toEqual([variant.publicBytes, 32, variant.ciphertextBytes, 32]);

      const encapsulated = variant.kem.encapsulate(publicKey, message);
      expect(Buffer.compare(Buffer.from(encapsulated.cipherText), expectedCiphertext)).toBe(0);
      expect(Buffer.compare(Buffer.from(encapsulated.sharedSecret), expectedSharedSecret)).toBe(0);
    });

    it("decapsulates an independent official ciphertext to the fixed shared secret", () => {
      expect(fixture.decapsulation).toMatchObject({
        tgId: variant.decapsulationGroup,
        tcId: variant.decapsulationCase,
      });
      const secretKey = Buffer.from(fixture.decapsulation.secretKeyHex, "hex");
      const ciphertext = Buffer.from(fixture.decapsulation.ciphertextHex, "hex");
      const expectedSharedSecret = Buffer.from(fixture.decapsulation.sharedSecretHex, "hex");
      expect([secretKey.length, ciphertext.length, expectedSharedSecret.length]).toEqual([
        variant.secretBytes,
        variant.ciphertextBytes,
        32,
      ]);
      expect(
        Buffer.compare(
          Buffer.from(variant.kem.decapsulate(ciphertext, secretKey)),
          expectedSharedSecret,
        ),
      ).toBe(0);
    });
  });
}
