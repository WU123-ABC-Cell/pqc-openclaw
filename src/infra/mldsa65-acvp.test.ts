// Public NIST ACVP-Server v1.1.0.43 sample vectors, pinned to commit
// 975de31eb83d87039ec88934fdc47d8c312b892d (vsId 42).
// KeyGen: ML-DSA-65 tgId 2 / tcId 26. Deterministic internal SigGen:
// ML-DSA-65 tgId 10 / tcId 147. Full official expected bytes are in the
// adjacent fixture; these tests exercise @noble/post-quantum's internal
// interfaces, not the product's UTF-8 payload protocol or FIPS certification.
import fs from "node:fs";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import { mlDsa65KeyPairMatches } from "./mldsa65-key-storage.js";

type AcvpFixture = {
  source: { commit: string; tag: string; vsId: number };
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

const fixture = JSON.parse(
  fs.readFileSync(new URL("./fixtures/ml-dsa-65-acvp-v1.1.0.43.json", import.meta.url), "utf8"),
) as AcvpFixture;

describe("NIST ACVP ML-DSA-65 sample known answers", () => {
  it("derives the official public and secret keys from the fixed KeyGen seed", () => {
    expect(fixture.source).toMatchObject({
      commit: "975de31eb83d87039ec88934fdc47d8c312b892d",
      tag: "v1.1.0.43",
      vsId: 42,
    });
    expect(fixture.keyGen).toMatchObject({ tgId: 2, tcId: 26 });
    const seed = Buffer.from(fixture.keyGen.seedHex, "hex");
    const expectedPublic = Buffer.from(fixture.keyGen.publicKeyHex, "hex");
    const expectedSecret = Buffer.from(fixture.keyGen.secretKeyHex, "hex");
    expect([seed.length, expectedPublic.length, expectedSecret.length]).toEqual([32, 1952, 4032]);

    const generated = ml_dsa65.keygen(seed);
    expect(Buffer.compare(Buffer.from(generated.publicKey), expectedPublic)).toBe(0);
    expect(Buffer.compare(Buffer.from(generated.secretKey), expectedSecret)).toBe(0);
    expect(mlDsa65KeyPairMatches(expectedPublic, expectedSecret)).toBe(true);
  });

  it("produces the official deterministic internal SigGen signature", () => {
    expect(fixture.sigGen).toMatchObject({ tgId: 10, tcId: 147 });
    const message = Buffer.from(fixture.sigGen.messageHex, "hex");
    const secretKey = Buffer.from(fixture.sigGen.secretKeyHex, "hex");
    const expectedSignature = Buffer.from(fixture.sigGen.signatureHex, "hex");
    expect([message.length, secretKey.length, expectedSignature.length]).toEqual([1, 4032, 3309]);

    const signature = ml_dsa65.internal.sign(message, secretKey, { extraEntropy: false });
    expect(Buffer.compare(Buffer.from(signature), expectedSignature)).toBe(0);
    const publicKey = ml_dsa65.getPublicKey(secretKey);
    expect(ml_dsa65.internal.verify(expectedSignature, message, publicKey)).toBe(true);
  });
});
