/**
 * Tests for client-side crypto primitives (src/lib/crypto/client.ts).
 *
 * These tests use the REAL Web Crypto API. No mocks of crypto.subtle,
 * no `btoa`-as-cipher hacks. Each test exercises the actual KDF, AES-GCM,
 * RSA-OAEP, and ECDH code paths.
 */
import { describe, it, expect } from "vitest";
import {
  bufToBase64,
  base64ToBuf,
  randomBytes,
  normalizePassword,
  canonicalJwkString,
  publicKeyFingerprint,
  constantTimeFingerprintCompare,
  generateEnrollCode,
  deriveMasterKey,
  argon2DefaultParams,
  pbkdf2LegacyParams,
  aesEncrypt,
  aesDecrypt,
  generateAesKey,
  exportAesKeyRaw,
  importAesKeyRaw,
  generateRsaKeyPair,
  exportPublicKeyJwk,
  exportPrivateKeyJwk,
  importPublicKeyJwk,
  importPrivateKeyJwk,
  encryptPrivateKey,
  decryptPrivateKey,
  wrapAesKeyWithRsaPublicKey,
  unwrapAesKeyWithRsaPrivateKey,
  signPop,
  verifyPop,
  buildPopMessage,
  generateEcdhKeyPair,
  exportEcdhPublicKeyJwk,
  importEcdhPublicKeyJwk,
  importEcdhPrivateKeyJwk,
  deriveEcdhSharedAesKey,
  wrapPrivateKeyForDevice,
  unwrapPrivateKeyForDevice,
  generateRecoveryMnemonic,
  validateRecoveryMnemonic,
} from "../client";

// ===== Encoding utilities =====
describe("bufToBase64 / base64ToBuf", () => {
  it("round-trips arbitrary bytes", () => {
    const input = new Uint8Array([0, 1, 2, 3, 255, 254, 253, 0, 128, 64, 32]);
    const b64 = bufToBase64(input);
    const out = base64ToBuf(b64);
    expect(Array.from(out)).toEqual(Array.from(input));
  });

  it("handles empty input", () => {
    const b64 = bufToBase64(new Uint8Array(0));
    expect(b64).toBe("");
    expect(base64ToBuf(b64).length).toBe(0);
  });

  it("produces valid base64 (only A-Za-z0-9+/=)", () => {
    const input = new Uint8Array(64);
    for (let i = 0; i < 64; i++) input[i] = i * 4;
    const b64 = bufToBase64(input);
    expect(b64).toMatch(/^[A-Za-z0-9+/=]*$/);
  });
});

describe("randomBytes", () => {
  it("returns the requested length", () => {
    expect(randomBytes(16).length).toBe(16);
    expect(randomBytes(32).length).toBe(32);
    expect(randomBytes(0).length).toBe(0);
  });

  it("returns different values on each call", () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });
});

describe("normalizePassword", () => {
  it("trims leading/trailing whitespace", () => {
    expect(normalizePassword("  secret  ")).toBe("secret");
  });

  it("NFKC-normalizes unicode equivalents", () => {
    // NFKC: full-width 'A' (U+FF21) → ASCII 'A' (U+0041)
    expect(normalizePassword("ＡＢＣ")).toBe("ABC");
  });
});

describe("canonicalJwkString", () => {
  it("produces the same string for the same JWK regardless of key order", () => {
    const jwk1 = { kty: "RSA", n: "abc", e: "AQAB" };
    const jwk2 = { e: "AQAB", kty: "RSA", n: "abc" };
    expect(canonicalJwkString(jwk1 as any)).toBe(canonicalJwkString(jwk2 as any));
  });
});

describe("constantTimeFingerprintCompare", () => {
  it("returns true for equal strings", () => {
    expect(constantTimeFingerprintCompare("abc", "abc")).toBe(true);
  });

  it("returns false for different strings", () => {
    expect(constantTimeFingerprintCompare("abc", "abd")).toBe(false);
  });

  it("returns false for different-length strings", () => {
    expect(constantTimeFingerprintCompare("abc", "abcd")).toBe(false);
  });
});

describe("generateEnrollCode", () => {
  it("produces a 6-digit string", () => {
    const code = generateEnrollCode();
    expect(code).toMatch(/^\d{6}$/);
  });

  it("produces different codes on successive calls", () => {
    const codes = new Set<string>();
    for (let i = 0; i < 20; i++) codes.add(generateEnrollCode());
    // 20 calls should produce more than 1 distinct code (statistically)
    expect(codes.size).toBeGreaterThan(1);
  });
});

// ===== KDF =====
describe("deriveMasterKey (PBKDF2)", () => {
  it("derives a non-extractable AES-GCM key with encrypt/decrypt usage", async () => {
    const params = pbkdf2LegacyParams(randomBytes(16), 1000); // low iterations for test speed
    const key = await deriveMasterKey("test-password", params);

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.algorithm.name).toBe("AES-GCM");
    expect(key.extractable).toBe(false);
    expect(key.usages).toContain("encrypt");
    expect(key.usages).toContain("decrypt");
  });

  it("derives the SAME key for the same password + params", async () => {
    const salt = randomBytes(16);
    const params = pbkdf2LegacyParams(salt, 1000);
    const k1 = await deriveMasterKey("test-password", params);
    const k2 = await deriveMasterKey("test-password", params);

    // Verify by encrypting the same plaintext with same IV
    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("hello");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k2, plaintext);
    expect(new Uint8Array(c1)).toEqual(new Uint8Array(c2));
  });

  it("derives DIFFERENT keys for different passwords", async () => {
    const salt = randomBytes(16);
    const params = pbkdf2LegacyParams(salt, 1000);
    const k1 = await deriveMasterKey("password-1", params);
    const k2 = await deriveMasterKey("password-2", params);

    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("hello");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k2, plaintext);
    expect(new Uint8Array(c1)).not.toEqual(new Uint8Array(c2));
  });

  it("derives DIFFERENT keys for different salts", async () => {
    const p1 = pbkdf2LegacyParams(randomBytes(16), 1000);
    const p2 = pbkdf2LegacyParams(randomBytes(16), 1000);
    const k1 = await deriveMasterKey("same-password", p1);
    const k2 = await deriveMasterKey("same-password", p2);

    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("hello");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k1, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k2, plaintext);
    expect(new Uint8Array(c1)).not.toEqual(new Uint8Array(c2));
  });
});

describe("argon2DefaultParams", () => {
  it("returns Argon2id params with the expected defaults", () => {
    const salt = randomBytes(16);
    const params = argon2DefaultParams(salt);
    expect(params.algorithm).toBe("argon2id");
    expect(params.salt).toBe(salt);
    expect(params.memoryKiB).toBe(65536); // 64 MiB
    expect(params.argon2Iterations).toBe(3);
    expect(params.parallelism).toBe(4);
  });
});

// ===== AES-GCM =====
describe("aesEncrypt / aesDecrypt", () => {
  it("round-trips arbitrary plaintext", async () => {
    const master = await deriveMasterKey(
      "test",
      pbkdf2LegacyParams(randomBytes(16), 1000)
    );
    const plaintext = "secret content";
    const { ciphertext, iv } = await aesEncrypt(master, plaintext);
    const decrypted = await aesDecrypt(master, ciphertext, iv);
    expect(decrypted).toBe(plaintext);
  });

  it("generates a unique IV per call", async () => {
    const master = await deriveMasterKey(
      "test",
      pbkdf2LegacyParams(randomBytes(16), 1000)
    );
    const plaintext = "same content";
    const a = await aesEncrypt(master, plaintext);
    const b = await aesEncrypt(master, plaintext);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("fails decryption with wrong key", async () => {
    const k1 = await deriveMasterKey("p1", pbkdf2LegacyParams(randomBytes(16), 1000));
    const k2 = await deriveMasterKey("p2", pbkdf2LegacyParams(randomBytes(16), 1000));
    const plaintext = "secret";
    const { ciphertext, iv } = await aesEncrypt(k1, plaintext);
    await expect(aesDecrypt(k2, ciphertext, iv)).rejects.toThrow();
  });

  it("fails decryption with tampered ciphertext", async () => {
    const master = await deriveMasterKey(
      "test",
      pbkdf2LegacyParams(randomBytes(16), 1000)
    );
    const plaintext = "secret";
    const { ciphertext, iv } = await aesEncrypt(master, plaintext);

    // Tamper with ciphertext (flip a bit)
    const ct = base64ToBuf(ciphertext);
    ct[0] ^= 1;
    const tampered = bufToBase64(ct);

    await expect(aesDecrypt(master, tampered, iv)).rejects.toThrow();
  });

  it("supports AAD (additional authenticated data)", async () => {
    const master = await deriveMasterKey(
      "test",
      pbkdf2LegacyParams(randomBytes(16), 1000)
    );
    const plaintext = "secret with context";
    const aad = "user:abc123|secret:def456";

    // Encrypt with AAD
    const { ciphertext, iv } = await aesEncrypt(master, plaintext, aad);

    // Decrypt with same AAD — succeeds
    const decrypted = await aesDecrypt(master, ciphertext, iv, aad);
    expect(decrypted).toBe(plaintext);

    // Decrypt with WRONG AAD — fails (GCM auth tag mismatch)
    await expect(
      aesDecrypt(master, ciphertext, iv, "user:abc123|secret:different")
    ).rejects.toThrow();

    // Decrypt with NO AAD — also fails
    await expect(aesDecrypt(master, ciphertext, iv)).rejects.toThrow();
  });

  it("supports Uint8Array AAD", async () => {
    const master = await deriveMasterKey(
      "test",
      pbkdf2LegacyParams(randomBytes(16), 1000)
    );
    const plaintext = "secret";
    const aad = new TextEncoder().encode("binary-aad");

    const { ciphertext, iv } = await aesEncrypt(master, plaintext, aad);
    const decrypted = await aesDecrypt(master, ciphertext, iv, aad);
    expect(decrypted).toBe(plaintext);
  });
});

describe("generateAesKey / exportAesKeyRaw / importAesKeyRaw", () => {
  it("round-trips a 256-bit AES key", async () => {
    const key = await generateAesKey();
    const raw = await exportAesKeyRaw(key);
    expect(raw.byteLength).toBe(32);
    const imported = await importAesKeyRaw(raw);
    expect(imported.algorithm.name).toBe("AES-GCM");
  });
});

// ===== RSA-OAEP =====
describe("RSA-OAEP key pair + wrap/unwrap", () => {
  it("generates a 2048-bit RSA-OAEP key pair", async () => {
    const pair = await generateRsaKeyPair();
    expect(pair.publicKey.algorithm.name).toBe("RSA-OAEP");
    expect(pair.privateKey.algorithm.name).toBe("RSA-OAEP");
  });

  it("round-trips JWK export/import for public key", async () => {
    const pair = await generateRsaKeyPair();
    const jwk = await exportPublicKeyJwk(pair.publicKey);
    expect(jwk.kty).toBe("RSA");
    expect(jwk.n).toBeTruthy();
    expect(jwk.e).toBeTruthy();
    const imported = await importPublicKeyJwk(jwk);
    expect(imported.algorithm.name).toBe("RSA-OAEP");
  });

  it("wrap/unwrap AES key with RSA-OAEP", async () => {
    const pair = await generateRsaKeyPair();
    const aes = await generateAesKey();
    const aesRaw = await exportAesKeyRaw(aes);

    const wrapped = await wrapAesKeyWithRsaPublicKey(aes, pair.publicKey);
    const unwrapped = await unwrapAesKeyWithRsaPrivateKey(wrapped, pair.privateKey);

    // The unwrapped key is non-extractable, so we verify by encrypting
    // the same plaintext with both and checking the ciphertexts match
    // (using the same IV — deterministic for AES-GCM with same key+IV+pt).
    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("verify-key-equality");

    // Re-import the original raw as non-extractable for fair comparison
    const aesNonExtractable = await importAesKeyRaw(aesRaw);

    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesNonExtractable, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, unwrapped, plaintext);
    expect(new Uint8Array(c1)).toEqual(new Uint8Array(c2));
  });
});

describe("encryptPrivateKey / decryptPrivateKey", () => {
  it("round-trips a private key encrypted with a master key", async () => {
    const master = await deriveMasterKey(
      "test",
      pbkdf2LegacyParams(randomBytes(16), 1000)
    );
    const pair = await generateRsaKeyPair();

    const encrypted = await encryptPrivateKey(master, pair.privateKey);
    const decryptedKey = await decryptPrivateKey(
      master,
      encrypted.encryptedJwk,
      encrypted.iv
    );
    expect(decryptedKey).toBeInstanceOf(CryptoKey);
    expect(decryptedKey.algorithm.name).toBe("RSA-OAEP");
  });
});

// ===== PoP (Proof of Possession) =====
describe("PoP signature", () => {
  it("signs and verifies a message with RSA-PSS", async () => {
    const pair = await generateRsaKeyPair();
    const email = "user@example.com";
    const fingerprint = "abc123fingerprint";
    const salt = "salt-base64==";
    const signature = await signPop(pair.privateKey, email, fingerprint, salt);
    const ok = await verifyPop(pair.publicKey, signature, email, fingerprint, salt);
    expect(ok).toBe(true);
  });

  it("rejects a tampered message (wrong email)", async () => {
    const pair = await generateRsaKeyPair();
    const signature = await signPop(
      pair.privateKey,
      "user@example.com",
      "fp",
      "salt"
    );
    const ok = await verifyPop(
      pair.publicKey,
      signature,
      "attacker@example.com",
      "fp",
      "salt"
    );
    expect(ok).toBe(false);
  });

  it("buildPopMessage produces deterministic bytes for the same input", () => {
    const m1 = buildPopMessage("user@example.com", "fingerprint-abc", "salt-xyz");
    const m2 = buildPopMessage("user@example.com", "fingerprint-abc", "salt-xyz");
    expect(Array.from(m1)).toEqual(Array.from(m2));
  });

  it("buildPopMessage produces different bytes for different inputs", () => {
    const m1 = buildPopMessage("user@example.com", "fingerprint-abc", "salt-xyz");
    const m2 = buildPopMessage("user@example.com", "fingerprint-def", "salt-xyz");
    expect(Array.from(m1)).not.toEqual(Array.from(m2));
  });
});

// ===== ECDH multi-device =====
describe("ECDH P-256 key exchange", () => {
  it("both parties derive the same shared AES key", async () => {
    // Device A
    const pairA = await generateEcdhKeyPair();
    const pubJwkA = await exportEcdhPublicKeyJwk(pairA.publicKey);

    // Device B
    const pairB = await generateEcdhKeyPair();
    const pubJwkB = await exportEcdhPublicKeyJwk(pairB.publicKey);

    // A derives shared key with B's public key (extractable for test comparison)
    const pubBForA = await importEcdhPublicKeyJwk(pubJwkB);
    const sharedA = await deriveEcdhSharedAesKey(pairA.privateKey, pubBForA, true);

    // B derives shared key with A's public key
    const pubAForB = await importEcdhPublicKeyJwk(pubJwkA);
    const sharedB = await deriveEcdhSharedAesKey(pairB.privateKey, pubAForB, true);

    // Both shared keys should produce the same raw bytes
    const rawA = await exportAesKeyRaw(sharedA);
    const rawB = await exportAesKeyRaw(sharedB);
    expect(Array.from(new Uint8Array(rawA))).toEqual(
      Array.from(new Uint8Array(rawB))
    );
  });

  it("wrap/unwrap private key for device", async () => {
    // Device A has the user's RSA private key
    const userPair = await generateRsaKeyPair();
    const userPrivJwk = await exportPrivateKeyJwk(userPair.privateKey);
    const userPrivJwkStr = JSON.stringify(userPrivJwk);

    // Device A generates its own ECDH pair, Device B generates its own
    const pairA = await generateEcdhKeyPair();
    const pairB = await generateEcdhKeyPair();
    const pubBForA = await importEcdhPublicKeyJwk(
      await exportEcdhPublicKeyJwk(pairB.publicKey)
    );

    // Device A derives the shared key with B's public key
    const sharedA = await deriveEcdhSharedAesKey(pairA.privateKey, pubBForA);

    // Device A wraps the user's RSA private key with the shared key
    const wrapped = await wrapPrivateKeyForDevice(userPrivJwkStr, sharedA);

    // Device B derives the same shared key with A's public key
    const pubAForB = await importEcdhPublicKeyJwk(
      await exportEcdhPublicKeyJwk(pairA.publicKey)
    );
    const sharedB = await deriveEcdhSharedAesKey(pairB.privateKey, pubAForB);

    // Device B unwraps using the same shared key
    const unwrapped = await unwrapPrivateKeyForDevice(
      wrapped.wrappedKey,
      wrapped.iv,
      sharedB
    );

    expect(unwrapped.algorithm.name).toBe("RSA-OAEP");
  });
});

// ===== Recovery mnemonic (BIP-39) =====
describe("BIP-39 recovery mnemonic", () => {
  it("generates a 24-word mnemonic", async () => {
    const { mnemonic } = await generateRecoveryMnemonic();
    const words = mnemonic.split(" ");
    expect(words.length).toBe(24);
  });

  it("generates different mnemonics on successive calls", async () => {
    const { mnemonic: m1 } = await generateRecoveryMnemonic();
    const { mnemonic: m2 } = await generateRecoveryMnemonic();
    expect(m1).not.toBe(m2);
  });

  it("validates a generated mnemonic as correct", async () => {
    const { mnemonic } = await generateRecoveryMnemonic();
    const ok = await validateRecoveryMnemonic(mnemonic);
    expect(ok).toBe(true);
  });

  it("rejects an invalid mnemonic", async () => {
    const ok = await validateRecoveryMnemonic(
      "apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple apple"
    );
    expect(ok).toBe(false);
  });
});

// ===== publicKeyFingerprint =====
describe("publicKeyFingerprint", () => {
  it("produces a hex string for a public key", async () => {
    const pair = await generateRsaKeyPair();
    const jwk = await exportPublicKeyJwk(pair.publicKey);
    const fp = await publicKeyFingerprint(jwk);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces the SAME fingerprint for the same JWK", async () => {
    const pair = await generateRsaKeyPair();
    const jwk = await exportPublicKeyJwk(pair.publicKey);
    const fp1 = await publicKeyFingerprint(jwk);
    const fp2 = await publicKeyFingerprint(jwk);
    expect(fp1).toBe(fp2);
  });

  it("produces DIFFERENT fingerprints for different keys", async () => {
    const pair1 = await generateRsaKeyPair();
    const pair2 = await generateRsaKeyPair();
    const fp1 = await publicKeyFingerprint(await exportPublicKeyJwk(pair1.publicKey));
    const fp2 = await publicKeyFingerprint(await exportPublicKeyJwk(pair2.publicKey));
    expect(fp1).not.toBe(fp2);
  });
});
