/**
 * Tests for additional client.ts functions: recovery, audit, fingerprint cache.
 */
import { describe, it, expect } from "vitest";
import {
  deriveMasterKey,
  pbkdf2LegacyParams,
  randomBytes,
  generateRsaKeyPair,
  exportPrivateKeyJwk,
  deriveRecoveryKey,
  encryptPrivateKeyForRecovery,
  decryptPrivateKeyForRecovery,
  encryptAuditEvent,
  decryptAuditEvent,
  publicKeyFingerprint,
  cachedPublicKeyFingerprint,
  generateEnrollCode,
  RECOVERY_ITERATIONS,
  type AuditCategory,
} from "../index";

function fastKdfParams() {
  return pbkdf2LegacyParams(randomBytes(16), 1000);
}

// ===== Recovery =====
describe("Recovery key (BIP-39 mnemonic → AES key)", () => {
  it("derives the same recovery key from the same mnemonic + salt", async () => {
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const salt = randomBytes(16);

    // Derive raw bytes via PBKDF2 (we can't export CryptoKey directly,
    // so verify by encrypting the same plaintext with both)
    const k1 = await deriveRecoveryKey(mnemonic, salt, 1000);
    const k2 = await deriveRecoveryKey(mnemonic, salt, 1000);

    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("verify-recovery");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k2, plaintext);
    expect(new Uint8Array(c1)).toEqual(new Uint8Array(c2));
  });

  it("derives DIFFERENT recovery keys for different mnemonics", async () => {
    const salt = randomBytes(16);
    const k1 = await deriveRecoveryKey(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      salt,
      1000
    );
    const k2 = await deriveRecoveryKey(
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
      salt,
      1000
    );

    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("verify-recovery");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k2, plaintext);
    expect(new Uint8Array(c1)).not.toEqual(new Uint8Array(c2));
  });
});

describe("encryptPrivateKeyForRecovery / decryptPrivateKeyForRecovery", () => {
  it("round-trips a private key encrypted with a recovery key", async () => {
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const recoveryKey = await deriveRecoveryKey(mnemonic, randomBytes(16), 1000);
    const pair = await generateRsaKeyPair();
    const privJwk = await exportPrivateKeyJwk(pair.privateKey);
    const privJwkStr = JSON.stringify(privJwk);

    const encrypted = await encryptPrivateKeyForRecovery(privJwkStr, recoveryKey);
    const decryptedKey = await decryptPrivateKeyForRecovery(
      encrypted.ciphertext,
      encrypted.iv,
      recoveryKey
    );
    expect(decryptedKey.algorithm.name).toBe("RSA-OAEP");
  });

  it("fails decryption with wrong recovery key", async () => {
    const mnemonicA =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const mnemonicB =
      "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const salt = randomBytes(16);
    const keyA = await deriveRecoveryKey(mnemonicA, salt, 1000);
    const keyB = await deriveRecoveryKey(mnemonicB, salt, 1000);

    const pair = await generateRsaKeyPair();
    const privJwkStr = JSON.stringify(await exportPrivateKeyJwk(pair.privateKey));

    const encrypted = await encryptPrivateKeyForRecovery(privJwkStr, keyA);
    await expect(
      decryptPrivateKeyForRecovery(encrypted.ciphertext, encrypted.iv, keyB)
    ).rejects.toThrow();
  });
});

// ===== Audit events =====
describe("encryptAuditEvent / decryptAuditEvent", () => {
  it("round-trips an audit event", async () => {
    const master = await deriveMasterKey("test", fastKdfParams());
    const { deriveAuditKey } = await import("../index");
    const auditKey = await deriveAuditKey(master);

    const event = {
      type: "test.event",
      timestamp: new Date().toISOString(),
      data: "some-data",
    };
    const enc = await encryptAuditEvent(auditKey, event);
    const dec = await decryptAuditEvent(auditKey, enc.encryptedEvent, enc.eventIv);
    expect(dec.type).toBe("test.event");
    expect(dec.data).toBe("some-data");
  });

  it("produces unique IVs per call", async () => {
    const master = await deriveMasterKey("test", fastKdfParams());
    const { deriveAuditKey } = await import("../index");
    const auditKey = await deriveAuditKey(master);

    const event = { type: "test", n: 1 };
    const a = await encryptAuditEvent(auditKey, event);
    const b = await encryptAuditEvent(auditKey, event);
    expect(a.eventIv).not.toBe(b.eventIv);
    expect(a.encryptedEvent).not.toBe(b.encryptedEvent);
  });
});

// ===== Fingerprint cache =====
describe("cachedPublicKeyFingerprint", () => {
  it("returns the same fingerprint as publicKeyFingerprint", async () => {
    const pair = await generateRsaKeyPair();
    const { exportPublicKeyJwk } = await import("../index");
    const jwk = await exportPublicKeyJwk(pair.publicKey);
    const fp1 = await publicKeyFingerprint(jwk);
    const fp2 = await cachedPublicKeyFingerprint(jwk);
    expect(fp1).toBe(fp2);
  });

  it("caches the result for repeated calls", async () => {
    const pair = await generateRsaKeyPair();
    const { exportPublicKeyJwk } = await import("../index");
    const jwk = await exportPublicKeyJwk(pair.publicKey);

    // First call populates cache
    const fp1 = await cachedPublicKeyFingerprint(jwk);
    // Second call returns cached value (same result)
    const fp2 = await cachedPublicKeyFingerprint(jwk);
    expect(fp1).toBe(fp2);
  });
});

// ===== generateEnrollCode =====
describe("generateEnrollCode", () => {
  it("produces a 6-digit numeric string", () => {
    const code = generateEnrollCode();
    expect(code).toMatch(/^\d{6}$/);
    expect(code.length).toBe(6);
  });
});

// ===== RECOVERY_ITERATIONS constant =====
describe("RECOVERY_ITERATIONS", () => {
  it("is a number >= 100,000", () => {
    expect(typeof RECOVERY_ITERATIONS).toBe("number");
    expect(RECOVERY_ITERATIONS).toBeGreaterThanOrEqual(100_000);
  });
});
