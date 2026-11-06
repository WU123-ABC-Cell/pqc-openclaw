// Public NIST ACVP-Server v1.1.0.43 FIPS204 samples at commit
// 975de31eb83d87039ec88934fdc47d8c312b892d (vsId 42).
// Fixed KeyGen and deterministic internal SigGen answers test the dependency,
// not OpenClaw's UTF-8 device-proof protocol or FIPS certification.
import fs from "node:fs";
import { ml_dsa44, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";

type AcvpFixture = {
  source: { commit: string; tag: string; vsId: number };
  parameterSet: string;
  keyGen: {
    tgId: number;
    tcId: number;
    seedHex: string;
    publicKeyHex: string;
    secretKeyHex: string;
  };
  sigGen: {
    tgId: number;
    tcId: number;
    messageHex: string;
    secretKeyHex: string;
    signatureHex: string;
  };
};

for (const variant of [
  {
    size: 44,
    dsa: ml_dsa44,
    keyGenGroup: 1,
    keyGenCase: 1,
    sigGenGroup: 8,
    sigGenCase: 110,
    publicBytes: 1312,
    secretBytes: 2560,
    signatureBytes: 2420,
  },
  {
    size: 87,
    dsa: ml_dsa87,
    keyGenGroup: 3,
    keyGenCase: 51,
    sigGenGroup: 12,
    sigGenCase: 172,
    publicBytes: 2592,
    secretBytes: 4896,
    signatureBytes: 4627,
  },
]) {
  const fixture = JSON.parse(
    fs.readFileSync(
      new URL(`./fixtures/ml-dsa-${variant.size}-acvp-v1.1.0.43.json`, import.meta.url),
      "utf8",
    ),
  ) as AcvpFixture;

  describe(`NIST ACVP ML-DSA-${variant.size} sample known answers`, () => {
    it("derives the official public and secret keys from the fixed KeyGen seed", () => {
      expect(fixture.source).toMatchObject({
        commit: "975de31eb83d87039ec88934fdc47d8c312b892d",
        tag: "v1.1.0.43",
        vsId: 42,
      });
      expect(fixture.parameterSet).toBe(`ML-DSA-${variant.size}`);
      expect(fixture.keyGen).toMatchObject({ tgId: variant.keyGenGroup, tcId: variant.keyGenCase });
      const seed = Buffer.from(fixture.keyGen.seedHex, "hex");
      const expectedPublic = Buffer.from(fixture.keyGen.publicKeyHex, "hex");
      const expectedSecret = Buffer.from(fixture.keyGen.secretKeyHex, "hex");
      expect([seed.length, expectedPublic.length, expectedSecret.length]).toEqual([
        32,
        variant.publicBytes,
        variant.secretBytes,
      ]);

      const generated = variant.dsa.keygen(seed);
      expect(Buffer.compare(Buffer.from(generated.publicKey), expectedPublic)).toBe(0);
      expect(Buffer.compare(Buffer.from(generated.secretKey), expectedSecret)).toBe(0);
      expect(
        Buffer.compare(Buffer.from(variant.dsa.getPublicKey(expectedSecret)), expectedPublic),
      ).toBe(0);
    });

    it("produces the official deterministic internal SigGen signature", () => {
      expect(fixture.sigGen).toMatchObject({ tgId: variant.sigGenGroup, tcId: variant.sigGenCase });
      const message = Buffer.from(fixture.sigGen.messageHex, "hex");
      const secretKey = Buffer.from(fixture.sigGen.secretKeyHex, "hex");
      const expectedSignature = Buffer.from(fixture.sigGen.signatureHex, "hex");
      expect([message.length, secretKey.length, expectedSignature.length]).toEqual([
        1,
        variant.secretBytes,
        variant.signatureBytes,
      ]);

      const signature = variant.dsa.internal.sign(message, secretKey, { extraEntropy: false });
      expect(Buffer.compare(Buffer.from(signature), expectedSignature)).toBe(0);
      const publicKey = variant.dsa.getPublicKey(secretKey);
      expect(variant.dsa.internal.verify(expectedSignature, message, publicKey)).toBe(true);
    });
  });
}
