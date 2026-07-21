import { describe, it, expect } from "vitest";
import { generateRecoveryMnemonic, validateRecoveryMnemonic, deriveRecoveryKey, encryptPrivateKeyForRecovery, decryptPrivateKeyForRecovery, exportPrivateKeyJwk, generateRsaKeyPair, randomBytes } from "@/lib/crypto";
describe("BIP-39 recovery E2E", () => {
  it("full recovery flow: generate → encrypt → decrypt → recover", async () => {
    const { mnemonic } = await generateRecoveryMnemonic();
    expect(mnemonic.split(" ").length).toBe(24);
    expect(await validateRecoveryMnemonic(mnemonic)).toBe(true);
    const salt = randomBytes(16);
    const recoveryKey = await deriveRecoveryKey(mnemonic, salt, 1000);
    const rsaPair = await generateRsaKeyPair();
    const privJwk = await exportPrivateKeyJwk(rsaPair.privateKey);
    const enc = await encryptPrivateKeyForRecovery(JSON.stringify(privJwk), recoveryKey);
    const recoveredKey = await decryptPrivateKeyForRecovery(enc.ciphertext, enc.iv, recoveryKey);
    expect(recoveredKey.algorithm.name).toBe("RSA-OAEP");
  });
});
