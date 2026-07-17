/**
 * Tests for key rotation (src/lib/crypto/rotation.ts).
 *
 * rotation.ts rotates RSA-OAEP wrapped keys when the user's RSA pair
 * changes (not when the master password changes — that's handled by
 * encryptPrivateKey/decryptPrivateKey with the master key directly).
 */
import { describe, it, expect } from "vitest";
import {
  generateRsaKeyPair,
  generateAesKey,
  wrapAesKeyWithRsaPublicKey,
  unwrapAesKeyWithRsaPrivateKey,
  exportAesKeyRaw,
  importAesKeyRaw,
  bufToBase64,
  base64ToBuf,
} from "../index";
import { rewrapSingleKey, rewrapAllKeys } from "../rotation";

describe("rewrapSingleKey", () => {
  it("re-wraps an AES key from the old RSA pair to the new RSA pair", async () => {
    // Old RSA pair
    const oldPair = await generateRsaKeyPair();
    // New RSA pair
    const newPair = await generateRsaKeyPair();
    // AES key (the secret)
    const aes = await generateAesKey();

    // Old wrapped key (encrypted with old public)
    const wrappedOld = await wrapAesKeyWithRsaPublicKey(aes, oldPair.publicKey);

    // Re-wrap to new pair
    const wrappedNew = await rewrapSingleKey(wrappedOld, oldPair.privateKey, newPair.publicKey);

    // Unwrap with new private key
    const unwrapped = await unwrapAesKeyWithRsaPrivateKey(wrappedNew, newPair.privateKey);

    // Verify by encrypting the same plaintext
    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("verify-rotation");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, unwrapped, plaintext);
    expect(new Uint8Array(c1)).toEqual(new Uint8Array(c2));
  });

  it("fails if old private key doesn't match old wrapped key", async () => {
    const oldPair = await generateRsaKeyPair();
    const newPair = await generateRsaKeyPair();
    const wrongPair = await generateRsaKeyPair();
    const aes = await generateAesKey();

    const wrappedOld = await wrapAesKeyWithRsaPublicKey(aes, oldPair.publicKey);

    // Try to rewrap with WRONG old private key
    await expect(
      rewrapSingleKey(wrappedOld, wrongPair.privateKey, newPair.publicKey)
    ).rejects.toThrow();
  });
});

describe("rewrapAllKeys", () => {
  it("rotates multiple wrapped keys in batch", async () => {
    const oldPair = await generateRsaKeyPair();
    const newPair = await generateRsaKeyPair();

    const aes1 = await generateAesKey();
    const aes2 = await generateAesKey();

    const wrapped1 = await wrapAesKeyWithRsaPublicKey(aes1, oldPair.publicKey);
    const wrapped2 = await wrapAesKeyWithRsaPublicKey(aes2, oldPair.publicKey);

    const result = await rewrapAllKeys(
      [
        { shareId: "share-1", wrappedKey: wrapped1 },
        { shareId: "share-2", wrappedKey: wrapped2 },
      ],
      { oldPrivateKey: oldPair.privateKey, newPublicKey: newPair.publicKey }
    );

    expect(result.rotated).toBe(2);
    expect(result.failed).toBe(0);
    expect(result.rewrappedKeys).toHaveLength(2);

    // Verify: each new wrapped key can be unwrapped with new private key
    for (const r of result.rewrappedKeys) {
      const unwrapped = await unwrapAesKeyWithRsaPrivateKey(r.newWrappedKey, newPair.privateKey);
      expect(unwrapped.algorithm.name).toBe("AES-GCM");
    }
  });

  it("counts failures when a key can't be unwrapped", async () => {
    const oldPair = await generateRsaKeyPair();
    const newPair = await generateRsaKeyPair();
    const wrongPair = await generateRsaKeyPair();

    const aes = await generateAesKey();
    const wrapped = await wrapAesKeyWithRsaPublicKey(aes, oldPair.publicKey);

    // Pass a fake/invalid wrapped key alongside the valid one
    const result = await rewrapAllKeys(
      [
        { shareId: "valid", wrappedKey: wrapped },
        { shareId: "invalid", wrappedKey: "!!!invalid-base64!!!" },
      ],
      { oldPrivateKey: oldPair.privateKey, newPublicKey: newPair.publicKey }
    );

    expect(result.rotated).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.rewrappedKeys).toHaveLength(1);
    expect(result.rewrappedKeys[0].shareId).toBe("valid");
  });
});
