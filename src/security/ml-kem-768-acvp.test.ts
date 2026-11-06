// Public NIST ACVP-Server v1.1.0.43 sample vectors, pinned to commit
// 975de31eb83d87039ec88934fdc47d8c312b892d (vsId 42 in each mode).
// ML-KEM-768 KeyGen and encapsulation: tgId 2 / tcId 26; decapsulation:
// tgId 5 / tcId 86. These fixed
// answers test the dependency's deterministic interfaces and the product's
// public-key derivation wrapper, not the full Nostr envelope or FIPS certification.
import fs from "node:fs";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { describe, expect, it } from "vitest";
import { deriveMlKem768PublicKey } from "./nip44-v2.js";

type AcvpFixture = {
  source: {
    commit: string;
    tag: string;
    revision: string;
    keyGenVsId: number;
    encapDecapVsId: number;
  };
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

const fixture = JSON.parse(
  fs.readFileSync(new URL("./fixtures/ml-kem-768-acvp-v1.1.0.43.json", import.meta.url), "utf8"),
) as AcvpFixture;

describe("NIST ACVP ML-KEM-768 sample known answers", () => {
  it("derives the official public and secret keys from fixed d and z", () => {
    expect(fixture.source).toMatchObject({
      commit: "975de31eb83d87039ec88934fdc47d8c312b892d",
      tag: "v1.1.0.43",
      revision: "FIPS203",
      keyGenVsId: 42,
    });
    expect(fixture.keyGen).toMatchObject({ tgId: 2, tcId: 26 });
    const d = Buffer.from(fixture.keyGen.dHex, "hex");
    const z = Buffer.from(fixture.keyGen.zHex, "hex");
    const expectedPublic = Buffer.from(fixture.keyGen.publicKeyHex, "hex");
    const expectedSecret = Buffer.from(fixture.keyGen.secretKeyHex, "hex");
    expect([d.length, z.length, expectedPublic.length, expectedSecret.length]).toEqual([
      32, 32, 1184, 2400,
    ]);

    const generated = ml_kem768.keygen(Buffer.concat([d, z]));
    expect(Buffer.compare(Buffer.from(generated.publicKey), expectedPublic)).toBe(0);
    expect(Buffer.compare(Buffer.from(generated.secretKey), expectedSecret)).toBe(0);
    expect(
      Buffer.compare(Buffer.from(deriveMlKem768PublicKey(expectedSecret)), expectedPublic),
    ).toBe(0);
  });

  it("encapsulates the official fixed ciphertext and shared secret", () => {
    expect(fixture.source).toMatchObject({ encapDecapVsId: 42 });
    expect(fixture.encapsulation).toMatchObject({ tgId: 2, tcId: 26 });
    const publicKey = Buffer.from(fixture.encapsulation.publicKeyHex, "hex");
    const message = Buffer.from(fixture.encapsulation.messageHex, "hex");
    const expectedCiphertext = Buffer.from(fixture.encapsulation.ciphertextHex, "hex");
    const expectedSharedSecret = Buffer.from(fixture.encapsulation.sharedSecretHex, "hex");
    expect([
      publicKey.length,
      message.length,
      expectedCiphertext.length,
      expectedSharedSecret.length,
    ]).toEqual([1184, 32, 1088, 32]);

    const encapsulated = ml_kem768.encapsulate(publicKey, message);
    expect(Buffer.compare(Buffer.from(encapsulated.cipherText), expectedCiphertext)).toBe(0);
    expect(Buffer.compare(Buffer.from(encapsulated.sharedSecret), expectedSharedSecret)).toBe(0);
  });

  it("decapsulates an independent official ciphertext to the fixed shared secret", () => {
    expect(fixture.decapsulation).toMatchObject({ tgId: 5, tcId: 86 });
    const secretKey = Buffer.from(fixture.decapsulation.secretKeyHex, "hex");
    const ciphertext = Buffer.from(fixture.decapsulation.ciphertextHex, "hex");
    const expectedSharedSecret = Buffer.from(fixture.decapsulation.sharedSecretHex, "hex");
    expect([secretKey.length, ciphertext.length, expectedSharedSecret.length]).toEqual([
      2400, 1088, 32,
    ]);
    expect(
      Buffer.compare(
        Buffer.from(ml_kem768.decapsulate(ciphertext, secretKey)),
        expectedSharedSecret,
      ),
    ).toBe(0);
  });
});
