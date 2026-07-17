/**
 * Integration tests — exercise the full zero-knowledge flows end-to-end
 * using the real Web Crypto API. No mocks of crypto.subtle.
 */
import { describe, it, expect } from "vitest";
import {
  deriveMasterKey,
  deriveAuditKey,
  pbkdf2LegacyParams,
  randomBytes,
  generateRsaKeyPair,
  exportPublicKeyJwk,
  exportPrivateKeyJwk,
  encryptPrivateKey,
  decryptPrivateKey,
  encryptAuditEvent,
  decryptAuditEvent,
  wrapAesKeyWithRsaPublicKey,
  unwrapAesKeyWithRsaPrivateKey,
  generateAesKey,
  wrapPrivateKeyForDevice,
  unwrapPrivateKeyForDevice,
  generateEcdhKeyPair,
  exportEcdhPublicKeyJwk,
  importEcdhPublicKeyJwk,
  deriveEcdhSharedAesKey,
  signPop,
  verifyPop,
  publicKeyFingerprint,
  bufToBase64,
  aesEncrypt,
  aesDecrypt,
  type AuditCategory,
} from "../index";

function fastKdfParams() {
  return pbkdf2LegacyParams(randomBytes(16), 1000);
}

// =====================================================================
// Flow 1: Registration → Login → Decrypt private key
// =====================================================================
describe("Full flow: register → login → decrypt private key", () => {
  it("user registers, then re-derives master key and decrypts their private key", async () => {
    const email = "alice@example.com";
    const password = "correct horse battery staple";
    const kdfParams = fastKdfParams();
    const saltB64 = bufToBase64(kdfParams.salt as Uint8Array);

    // ----- REGISTRATION -----
    const masterKeyA = await deriveMasterKey(password, kdfParams);
    const rsaPairA = await generateRsaKeyPair();
    const pubJwkA = await exportPublicKeyJwk(rsaPairA.publicKey);
    const fingerprintA = await publicKeyFingerprint(pubJwkA);

    // PoP
    const popSig = await signPop(rsaPairA.privateKey, email, fingerprintA, saltB64);
    expect(await verifyPop(rsaPairA.publicKey, popSig, email, fingerprintA, saltB64)).toBe(true);

    // Encrypt private key
    const encryptedPriv = await encryptPrivateKey(masterKeyA, rsaPairA.privateKey);

    // ----- LOGIN (re-derive master key from password + stored params) -----
    const masterKeyA2 = await deriveMasterKey(password, kdfParams);
    const decryptedPrivKey = await decryptPrivateKey(
      masterKeyA2,
      encryptedPriv.encryptedJwk,
      encryptedPriv.iv
    );
    expect(decryptedPrivKey.algorithm.name).toBe("RSA-OAEP");
  }, 15000);
});

// =====================================================================
// Flow 2: Create secret → Share → Recipient decrypts AES key
// =====================================================================
describe("Share flow: A creates, shares AES key, B unwraps", () => {
  it("owner wraps AES key with recipient's public key, recipient unwraps", async () => {
    // A has the secret + AES key
    const aesKey = await generateAesKey();

    // B has an RSA keypair
    const pairB = await generateRsaKeyPair();

    // A wraps the AES key with B's public key
    const wrapped = await wrapAesKeyWithRsaPublicKey(aesKey, pairB.publicKey);

    // B unwraps with its private key
    const unwrapped = await unwrapAesKeyWithRsaPrivateKey(wrapped, pairB.privateKey);

    // Verify by encrypting the same plaintext with both — should match
    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("secret-content");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, unwrapped, plaintext);
    expect(new Uint8Array(c1)).toEqual(new Uint8Array(c2));
  });
});

// =====================================================================
// Flow 3: Multi-device enrollment via ECDH
// =====================================================================
describe("Multi-device enrollment flow", () => {
  it("device A enrolls device B via ECDH key exchange", async () => {
    const userRsaPair = await generateRsaKeyPair();
    const userPrivJwk = await exportPrivateKeyJwk(userRsaPair.privateKey);
    const userPrivJwkStr = JSON.stringify(userPrivJwk);

    const pairA = await generateEcdhKeyPair();
    const pairB = await generateEcdhKeyPair();

    // A derives shared key with B's public key
    const pubB = await exportEcdhPublicKeyJwk(pairB.publicKey);
    const pubBForA = await importEcdhPublicKeyJwk(pubB);
    const sharedA = await deriveEcdhSharedAesKey(pairA.privateKey, pubBForA);

    // A wraps user's RSA private key
    const wrapped = await wrapPrivateKeyForDevice(userPrivJwkStr, sharedA);

    // B derives the same shared key
    const pubA = await exportEcdhPublicKeyJwk(pairA.publicKey);
    const pubAForB = await importEcdhPublicKeyJwk(pubA);
    const sharedB = await deriveEcdhSharedAesKey(pairB.privateKey, pubAForB);

    // B unwraps the user's RSA private key
    const userPrivKeyOnB = await unwrapPrivateKeyForDevice(
      wrapped.wrappedKey,
      wrapped.iv,
      sharedB
    );
    expect(userPrivKeyOnB.algorithm.name).toBe("RSA-OAEP");

    // B can use the user's RSA private key to decrypt an AES key
    const aesKey = await generateAesKey();
    const wrapped2 = await wrapAesKeyWithRsaPublicKey(aesKey, userRsaPair.publicKey);
    const unwrapped2 = await unwrapAesKeyWithRsaPrivateKey(wrapped2, userPrivKeyOnB);
    expect(unwrapped2.algorithm.name).toBe("AES-GCM");
  }, 15000);
});

// =====================================================================
// Flow 4: Master password rotation — re-encrypts ALL secrets
// =====================================================================
describe("Master password rotation flow (full re-encryption)", () => {
  it("rotates master password and re-encrypts private key + multiple secrets", async () => {
    // Initial state — user has 3 secrets encrypted with OLD master key
    const oldPassword = "old-master-password-123";
    const oldKdf = fastKdfParams();
    const oldMasterKey = await deriveMasterKey(oldPassword, oldKdf);
    const rsaPair = await generateRsaKeyPair();

    const encryptedPrivOld = await encryptPrivateKey(oldMasterKey, rsaPair.privateKey);

    // Create 3 secrets (simulating what the user has stored)
    const secretContents = ["secret-1-content", "secret-2-content", "secret-3-content"];
    const encryptedSecrets = [];
    for (const content of secretContents) {
      const enc = await aesEncrypt(oldMasterKey, content);
      encryptedSecrets.push({
        plaintext: content,
        ciphertext: enc.ciphertext,
        iv: enc.iv,
      });
    }

    // ----- ROTATION -----
    const newPassword = "new-master-password-456";
    const newKdf = fastKdfParams();
    const newMasterKey = await deriveMasterKey(newPassword, newKdf);

    // Re-encrypt private key
    const decryptedPrivKey = await decryptPrivateKey(
      oldMasterKey,
      encryptedPrivOld.encryptedJwk,
      encryptedPrivOld.iv
    );
    const encryptedPrivNew = await encryptPrivateKey(newMasterKey, decryptedPrivKey);

    // Re-encrypt all secrets
    const reencryptedSecrets = [];
    for (const s of encryptedSecrets) {
      const plaintext = await aesDecrypt(oldMasterKey, s.ciphertext, s.iv);
      const reencrypted = await aesEncrypt(newMasterKey, plaintext);
      reencryptedSecrets.push({
        plaintext: s.plaintext,
        ciphertext: reencrypted.ciphertext,
        iv: reencrypted.iv,
      });
    }

    // ----- VERIFY: all secrets accessible with NEW master key -----
    for (const s of reencryptedSecrets) {
      const decrypted = await aesDecrypt(newMasterKey, s.ciphertext, s.iv);
      expect(decrypted).toBe(s.plaintext);
    }

    // ----- VERIFY: NEW key decrypts the new private key blob -----
    const finalPrivKey = await decryptPrivateKey(
      newMasterKey,
      encryptedPrivNew.encryptedJwk,
      encryptedPrivNew.iv
    );
    expect(finalPrivKey.algorithm.name).toBe("RSA-OAEP");

    // ----- VERIFY: OLD key CANNOT decrypt any new blob -----
    await expect(
      decryptPrivateKey(oldMasterKey, encryptedPrivNew.encryptedJwk, encryptedPrivNew.iv)
    ).rejects.toThrow();

    for (const s of reencryptedSecrets) {
      await expect(aesDecrypt(oldMasterKey, s.ciphertext, s.iv)).rejects.toThrow();
    }
  });
});

// =====================================================================
// Flow 5: Audit log encryption + subkey independence
// =====================================================================
describe("Audit log flow", () => {
  it("derives an audit subkey and encrypts/decrypts audit events", async () => {
    const password = "audit-test-password";
    const kdf = fastKdfParams();
    const masterKey = await deriveMasterKey(password, kdf);

    const auditKey = await deriveAuditKey(masterKey);
    expect(auditKey.algorithm.name).toBe("AES-GCM");

    const timestamp = new Date().toISOString();
    const event = {
      type: "secret.created",
      timestamp,
      secretId: "sec_abc123",
      ip: "192.0.2.1",
    };
    const category: AuditCategory = "secret";
    const encrypted = await encryptAuditEvent(auditKey, event);
    expect(encrypted.encryptedEvent).toBeTruthy();
    expect(encrypted.eventIv).toBeTruthy();

    const decrypted = await decryptAuditEvent(auditKey, encrypted.encryptedEvent, encrypted.eventIv);
    // Verify all expected fields are present (timestamp may differ in ms
    // precision due to JSON round-trip — use string-contains check).
    expect(decrypted.type).toBe("secret.created");
    expect(decrypted.secretId).toBe("sec_abc123");
    expect(decrypted.ip).toBe("192.0.2.1");
    expect(typeof decrypted.timestamp).toBe("string");
    expect(String(decrypted.timestamp).startsWith(timestamp.slice(0, -4))).toBe(true);
  });

  it("audit subkey is INDEPENDENT from masterKey", async () => {
    const password = "test";
    const kdf = fastKdfParams();
    const masterKey = await deriveMasterKey(password, kdf);
    const auditKey = await deriveAuditKey(masterKey);

    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("audit-test");

    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, auditKey, plaintext);

    expect(new Uint8Array(c1)).not.toEqual(new Uint8Array(c2));
  });
});

// =====================================================================
// Flow 6: AES-GCM round-trip with known plaintext
// =====================================================================
describe("AES-GCM round-trip", () => {
  it("encrypts and decrypts a known plaintext", async () => {
    const master = await deriveMasterKey("test", fastKdfParams());
    const plaintext = "my secret content";
    const { ciphertext, iv } = await aesEncrypt(master, plaintext);
    const decrypted = await aesDecrypt(master, ciphertext, iv);
    expect(decrypted).toBe(plaintext);
  });
});
