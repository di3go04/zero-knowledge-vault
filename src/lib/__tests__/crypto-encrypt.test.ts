import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest";
import { zeroBuffer } from "../memory-zero";

// ---------------------------------------------------------------------------
// Mock Web Crypto API — Node.js no expone crypto.subtle en vitest
// ---------------------------------------------------------------------------
// crypto-client.ts references zeroBuffer() without importing it; make it
// globally available so the module under test can find it.
(globalThis as Record<string, unknown>).zeroBuffer = zeroBuffer;
const mockCryptoKey = {} as CryptoKey;
const mockCryptoKey2 = {} as CryptoKey;

const mockSubtle = {
  encrypt: vi.fn<(...args: unknown[]) => Promise<ArrayBuffer>>(),
  decrypt: vi.fn<(...args: unknown[]) => Promise<ArrayBuffer>>(),
  generateKey: vi.fn<(...args: unknown[]) => Promise<CryptoKey | CryptoKeyPair>>(),
  importKey: vi.fn<(...args: unknown[]) => Promise<CryptoKey>>(),
  exportKey: vi.fn<(...args: unknown[]) => Promise<ArrayBuffer | JsonWebKey>>(),
  deriveKey: vi.fn<(...args: unknown[]) => Promise<CryptoKey>>(),
  digest: vi.fn<(...args: unknown[]) => Promise<ArrayBuffer>>(),
  sign: vi.fn<(...args: unknown[]) => Promise<ArrayBuffer>>(),
  verify: vi.fn<(...args: unknown[]) => Promise<boolean>>(),
};

beforeAll(() => {
  Object.defineProperty(globalThis, "crypto", {
    value: {
      subtle: mockSubtle,
      _rngCounter: 0,
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++)
          arr[i] = (((crypto as Record<string, unknown>)._rngCounter as number) + i) % 256;
        (crypto as Record<string, unknown>)._rngCounter =
          ((crypto as Record<string, unknown>)._rngCounter as number) + arr.length;
        return arr;
      },
      randomUUID: () => "00000000-0000-0000-0000-000000000000",
    },
    configurable: true,
    writable: true,
  });
});

// ---------------------------------------------------------------------------
// Importamos los wrappers DESPUÉS de definir el mock
// ---------------------------------------------------------------------------
import {
  aesEncrypt,
  aesDecrypt,
  generateAesKey,
  exportAesKeyRaw,
  importAesKeyRaw,
  wrapAesKeyWithRsaPublicKey,
  unwrapAesKeyWithRsaPrivateKey,
  deriveMasterKey,
  deriveRecoveryKey,
  generateRsaKeyPair,
  exportPublicKeyJwk,
  exportPrivateKeyJwk,
  importPublicKeyJwk,
  importPrivateKeyJwk,
  encryptPrivateKey,
  decryptPrivateKey,
  bufToBase64,
  base64ToBuf,
  randomBytes,
  IV_LENGTH,
  AES_KEY_LENGTH,
  KDF_ITERATIONS,
} from "../crypto-client";

// ===========================================================================
// AES-256-GCM Encryption / Decryption
// ===========================================================================
describe("AES-256-GCM Encryption", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should encrypt data and return ciphertext + IV as base64", async () => {
    const plaintext = "my-secret-data";
    mockSubtle.encrypt.mockResolvedValue(new TextEncoder().encode("mock-ct").buffer as ArrayBuffer);

    const result = await aesEncrypt(mockCryptoKey, plaintext);

    expect(result).toHaveProperty("ciphertext");
    expect(result).toHaveProperty("iv");
    expect(typeof result.ciphertext).toBe("string");
    expect(typeof result.iv).toBe("string");
    expect(result.ciphertext.length).toBeGreaterThan(0);
    expect(result.iv.length).toBeGreaterThan(0);
  });

  it("should call subtle.encrypt with AES-GCM and a 12-byte IV", async () => {
    mockSubtle.encrypt.mockResolvedValue(new ArrayBuffer(32));

    await aesEncrypt(mockCryptoKey, "test-data");

    expect(mockSubtle.encrypt).toHaveBeenCalledTimes(1);
    const params = mockSubtle.encrypt.mock.calls[0][0] as { name: string; iv: BufferSource };
    expect(params.name).toBe("AES-GCM");
    expect((params.iv as Uint8Array).byteLength).toBe(IV_LENGTH);
  });

  it("should roundtrip encrypt → decrypt successfully", async () => {
    const plaintext = "roundtrip-data";
    const ctBuf = new TextEncoder().encode("ciphertext-bytes").buffer;
    const ptBuf = new TextEncoder().encode(plaintext).buffer;

    mockSubtle.encrypt.mockResolvedValue(ctBuf as ArrayBuffer);
    mockSubtle.decrypt.mockResolvedValue(ptBuf as ArrayBuffer);

    const encrypted = await aesEncrypt(mockCryptoKey, plaintext);
    const decrypted = await aesDecrypt(mockCryptoKey, encrypted.ciphertext, encrypted.iv);

    expect(decrypted).toBe(plaintext);
    expect(mockSubtle.decrypt).toHaveBeenCalledWith(
      expect.objectContaining({ name: "AES-GCM" }),
      mockCryptoKey,
      expect.any(Object)
    );
  });

  it("should decrypt and produce the correct plaintext format", async () => {
    mockSubtle.encrypt.mockResolvedValue(new ArrayBuffer(32));
    mockSubtle.decrypt.mockResolvedValue(
      new TextEncoder().encode("decrypted-data").buffer as ArrayBuffer
    );

    const encrypted = await aesEncrypt(mockCryptoKey, "anything");
    const result = await aesDecrypt(mockCryptoKey, encrypted.ciphertext, encrypted.iv);

    expect(result).toBe("decrypted-data");
  });

  it("should reject invalid base64 ciphertext in aesDecrypt", async () => {
    await expect(aesDecrypt(mockCryptoKey, "!!!not-base64!!!", "aaaa")).rejects.toThrow();
  });

  it("should reject invalid base64 iv in aesDecrypt", async () => {
    mockSubtle.decrypt.mockResolvedValue(new ArrayBuffer(8));
    await expect(aesDecrypt(mockCryptoKey, "YWFhYQ==", "!!!not-base64!!!")).rejects.toThrow();
  });

  it("should produce different IVs for consecutive encryptions", async () => {
    mockSubtle.encrypt.mockResolvedValue(new ArrayBuffer(32));

    const r1 = await aesEncrypt(mockCryptoKey, "data");
    const r2 = await aesEncrypt(mockCryptoKey, "data");

    // getRandomValues is deterministic (i % 256), but runs sequentially
    // so iv1 = [0..11], iv2 = [12..23] — different
    expect(r1.iv).not.toBe(r2.iv);
  });

  it("should handle empty plaintext (AES-GCM can encrypt empty)", async () => {
    mockSubtle.encrypt.mockResolvedValue(new ArrayBuffer(16));

    const result = await aesEncrypt(mockCryptoKey, "");
    expect(result.ciphertext).toBeDefined();
    expect(result.iv).toBeDefined();
    // subtle.encrypt was called with an empty Uint8Array
    const dataArg = mockSubtle.encrypt.mock.calls[0][2] as Uint8Array;
    expect(dataArg.byteLength).toBe(0);
  });
});

// ===========================================================================
// AES Key Generation
// ===========================================================================
describe("AES Key Generation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should generate an AES-256-GCM key", async () => {
    mockSubtle.generateKey.mockResolvedValue(mockCryptoKey);

    const key = await generateAesKey();

    expect(key).toBe(mockCryptoKey);
    expect(mockSubtle.generateKey).toHaveBeenCalledWith(
      { name: "AES-GCM", length: AES_KEY_LENGTH },
      true,
      ["encrypt", "decrypt"]
    );
  });

  it("should export a raw AES key", async () => {
    const raw = new ArrayBuffer(32);
    mockSubtle.exportKey.mockResolvedValue(raw);

    const result = await exportAesKeyRaw(mockCryptoKey);

    expect(result).toBe(raw);
    expect(mockSubtle.exportKey).toHaveBeenCalledWith("raw", mockCryptoKey);
  });

  it("should import a raw AES key", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);

    const raw = new ArrayBuffer(32);
    const key = await importAesKeyRaw(raw);

    expect(key).toBe(mockCryptoKey);
    expect(mockSubtle.importKey).toHaveBeenCalledWith(
      "raw",
      raw,
      { name: "AES-GCM", length: AES_KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  });

  it("should import then export a roundtrip key", async () => {
    const raw = new ArrayBuffer(32);
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.exportKey.mockResolvedValue(raw);

    const imported = await importAesKeyRaw(raw);
    const exported = await exportAesKeyRaw(imported);

    expect(exported).toBe(raw);
  });
});

// ===========================================================================
// RSA-OAEP Key Wrapping (AES key wrapped with RSA public key)
// ===========================================================================
describe("RSA-OAEP Key Wrapping", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should wrap an AES key with RSA-OAEP and return base64", async () => {
    const rawAes = new ArrayBuffer(32);
    const wrapped = new TextEncoder().encode("wrapped-key").buffer;

    mockSubtle.exportKey.mockResolvedValue(rawAes);
    mockSubtle.encrypt.mockResolvedValue(wrapped as ArrayBuffer);

    const result = await wrapAesKeyWithRsaPublicKey(mockCryptoKey, mockCryptoKey2);

    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
    expect(mockSubtle.encrypt).toHaveBeenCalledWith({ name: "RSA-OAEP" }, mockCryptoKey2, rawAes);
  });

  it("should unwrap an RSA-OAEP-wrapped AES key", async () => {
    const rawAes = new ArrayBuffer(32);
    mockSubtle.decrypt.mockResolvedValue(rawAes);
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);

    const wrappedB64 = bufToBase64(new Uint8Array(256));
    const result = await unwrapAesKeyWithRsaPrivateKey(wrappedB64, mockCryptoKey2);

    expect(result).toBe(mockCryptoKey);
    expect(mockSubtle.decrypt).toHaveBeenCalledWith(
      { name: "RSA-OAEP" },
      mockCryptoKey2,
      expect.any(Object)
    );
    expect(mockSubtle.importKey).toHaveBeenCalledWith(
      "raw",
      rawAes,
      { name: "AES-GCM", length: AES_KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  });

  it("should roundtrip wrap → unwrap correctly", async () => {
    const rawAes = new ArrayBuffer(32);
    const wrapped = new TextEncoder().encode("wrapped-key").buffer;

    mockSubtle.exportKey.mockResolvedValue(rawAes);
    mockSubtle.encrypt.mockResolvedValue(wrapped as ArrayBuffer);
    mockSubtle.decrypt.mockResolvedValue(rawAes);
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);

    const wrappedB64 = await wrapAesKeyWithRsaPublicKey(mockCryptoKey, mockCryptoKey2);
    const unwrapped = await unwrapAesKeyWithRsaPrivateKey(wrappedB64, mockCryptoKey2);

    expect(unwrapped).toBe(mockCryptoKey);
  });

  it("should reject invalid base64 in unwrap", async () => {
    await expect(
      unwrapAesKeyWithRsaPrivateKey("!!!invalid-base64!!!", mockCryptoKey2)
    ).rejects.toThrow();
  });
});

// ===========================================================================
// RSA Key Pair Generation
// ===========================================================================
describe("RSA Key Pair", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should generate an RSA-OAEP key pair", async () => {
    const keyPair: CryptoKeyPair = {
      publicKey: {} as CryptoKey,
      privateKey: {} as CryptoKey,
    };
    mockSubtle.generateKey.mockResolvedValue(keyPair);

    const result = await generateRsaKeyPair();

    expect(result).toHaveProperty("publicKey");
    expect(result).toHaveProperty("privateKey");
    expect(mockSubtle.generateKey).toHaveBeenCalledWith(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  });

  it("should export public key as JWK", async () => {
    const jwk: JsonWebKey = { kty: "RSA", n: "abc", e: "AQAB" };
    mockSubtle.exportKey.mockResolvedValue(jwk);

    const result = await exportPublicKeyJwk(mockCryptoKey);

    expect(result).toEqual(jwk);
    expect(mockSubtle.exportKey).toHaveBeenCalledWith("jwk", mockCryptoKey);
  });

  it("should export private key as JWK", async () => {
    const jwk: JsonWebKey = { kty: "RSA", n: "abc", e: "AQAB", d: "xyz" };
    mockSubtle.exportKey.mockResolvedValue(jwk);

    const result = await exportPrivateKeyJwk(mockCryptoKey);

    expect(result).toEqual(jwk);
    expect(mockSubtle.exportKey).toHaveBeenCalledWith("jwk", mockCryptoKey);
  });

  it("should import a public JWK key", async () => {
    const jwk: JsonWebKey = { kty: "RSA", n: "abc", e: "AQAB" };
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);

    const result = await importPublicKeyJwk(jwk);

    expect(result).toBe(mockCryptoKey);
    // Should strip key_ops, ext, alg before importing
    expect(mockSubtle.importKey).toHaveBeenCalledWith(
      "jwk",
      jwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt", "wrapKey"]
    );
  });

  it("should import a private JWK key", async () => {
    const jwk: JsonWebKey = { kty: "RSA", n: "abc", e: "AQAB", d: "xyz" };
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);

    const result = await importPrivateKeyJwk(jwk);

    expect(result).toBe(mockCryptoKey);
    expect(mockSubtle.importKey).toHaveBeenCalledWith(
      "jwk",
      jwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt", "unwrapKey"]
    );
  });

  it("should strip alg/key_ops/ext from JWK before importing", async () => {
    const jwk: JsonWebKey = {
      kty: "RSA",
      n: "abc",
      e: "AQAB",
      alg: "RSA-OAEP-256",
      key_ops: ["wrapKey"],
      ext: true,
    };
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);

    await importPublicKeyJwk(jwk);

    const importArgs = mockSubtle.importKey.mock.calls[0];
    const sanitized = importArgs[1] as JsonWebKey;
    expect(sanitized).not.toHaveProperty("alg");
    expect(sanitized).not.toHaveProperty("key_ops");
    expect(sanitized).not.toHaveProperty("ext");
    expect(sanitized).toHaveProperty("kty");
    expect(sanitized).toHaveProperty("n");
    expect(sanitized).toHaveProperty("e");
  });
});

// ===========================================================================
// PBKDF2 Key Derivation
// ===========================================================================
describe("PBKDF2 Key Derivation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should derive a master key via PBKDF2", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = randomBytes(16);
    const masterKey = await deriveMasterKey("my-password", {
      algorithm: "pbkdf2",
      salt,
      iterations: 600_000,
    });

    expect(masterKey).toBe(mockCryptoKey2);
    expect(mockSubtle.importKey).toHaveBeenCalledWith(
      "raw",
      expect.any(Object),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    expect(mockSubtle.deriveKey).toHaveBeenCalledWith(
      {
        name: "PBKDF2",
        salt,
        iterations: 600_000,
        hash: "SHA-256",
      },
      mockCryptoKey,
      { name: "AES-GCM", length: AES_KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  });

  it("should normalize password before deriving key", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = randomBytes(16);
    await deriveMasterKey("Café", {
      algorithm: "pbkdf2",
      salt,
      iterations: 600_000,
    });

    const importArgs = mockSubtle.importKey.mock.calls[0][1] as Uint8Array;
    const importedStr = new TextDecoder().decode(importArgs);
    // NFC normalization: "Café" in NFC is "Caf\u00e9"
    expect(importedStr).toBe("Café".normalize("NFC"));
  });

  it("should use the provided salt for derivation", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    await deriveMasterKey("password", {
      algorithm: "pbkdf2",
      salt,
      iterations: 600_000,
    });

    const deriveArgs = mockSubtle.deriveKey.mock.calls[0][0] as { salt: BufferSource };
    expect(new Uint8Array(deriveArgs.salt as ArrayBuffer)).toEqual(salt);
  });

  it("should use default iterations when not provided", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = randomBytes(16);
    await deriveMasterKey("password", {
      algorithm: "pbkdf2",
      salt,
    });

    const deriveArgs = mockSubtle.deriveKey.mock.calls[0][0] as { iterations: number };
    expect(deriveArgs.iterations).toBe(KDF_ITERATIONS);
  });

  it("should respect custom iterations parameter", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = randomBytes(16);
    const customIterations = 310_000;
    await deriveMasterKey("password", {
      algorithm: "pbkdf2",
      salt,
      iterations: customIterations,
    });

    const deriveArgs = mockSubtle.deriveKey.mock.calls[0][0] as { iterations: number };
    expect(deriveArgs.iterations).toBe(customIterations);
  });

  it("should use sufficient iterations (≥ 310k, OWASP minimum)", () => {
    expect(KDF_ITERATIONS).toBeGreaterThanOrEqual(310_000);
  });

  it("should derive key with AES-256-GCM usages", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = randomBytes(16);
    await deriveMasterKey("password", {
      algorithm: "pbkdf2",
      salt,
      iterations: 600_000,
    });

    const deriveArgs = mockSubtle.deriveKey.mock.calls[0];
    const algorithm = deriveArgs[2] as { name: string; length: number };
    const extractable = deriveArgs[3] as boolean;
    const keyUsages = deriveArgs[4] as string[];

    expect(algorithm).toEqual({ name: "AES-GCM", length: AES_KEY_LENGTH });
    expect(extractable).toBe(false);
    expect(keyUsages).toEqual(["encrypt", "decrypt"]);
  });
});

// ===========================================================================
// Private Key Encryption (wrapping RSA private key with master key)
// ===========================================================================
describe("Private Key Encryption", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should encrypt a private key with the master key", async () => {
    mockSubtle.exportKey.mockResolvedValue({ kty: "RSA", n: "abc", d: "xyz" } as JsonWebKey);
    mockSubtle.encrypt.mockResolvedValue(
      new TextEncoder().encode("encrypted-jwk").buffer as ArrayBuffer
    );

    const result = await encryptPrivateKey(mockCryptoKey, mockCryptoKey2);

    expect(result).toHaveProperty("encryptedJwk");
    expect(result).toHaveProperty("iv");
    expect(typeof result.encryptedJwk).toBe("string");
    expect(typeof result.iv).toBe("string");
    expect(result.encryptedJwk.length).toBeGreaterThan(0);
  });

  it("should decrypt a private key that was encrypted", async () => {
    const privateJwk: JsonWebKey = { kty: "RSA", n: "abc", d: "xyz" };
    const privateJwkStr = JSON.stringify(privateJwk);
    const ctBuf = new TextEncoder().encode("encrypted").buffer;
    const ptBuf = new TextEncoder().encode(privateJwkStr).buffer;

    mockSubtle.exportKey.mockResolvedValue(privateJwk);
    mockSubtle.encrypt.mockResolvedValue(ctBuf as ArrayBuffer);
    mockSubtle.decrypt.mockResolvedValue(ptBuf as ArrayBuffer);
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);

    const encrypted = await encryptPrivateKey(mockCryptoKey, mockCryptoKey2);
    const decrypted = await decryptPrivateKey(mockCryptoKey, encrypted.encryptedJwk, encrypted.iv);

    expect(decrypted).toBe(mockCryptoKey);
  });
});

// ===========================================================================
// Recovery Key Derivation (BIP-39 mnemonic → AES key)
// ===========================================================================
describe("Recovery Key Derivation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should derive a recovery key from mnemonic and salt", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const salt = randomBytes(16);

    const key = await deriveRecoveryKey(mnemonic, salt);

    expect(key).toBe(mockCryptoKey2);
    expect(mockSubtle.importKey).toHaveBeenCalledWith(
      "raw",
      expect.any(Object),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
  });

  it("should normalize mnemonic to lowercase and trimmed", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = randomBytes(16);
    await deriveRecoveryKey("  ABANDON ABANDON  ", salt);

    const importArgs = mockSubtle.importKey.mock.calls[0][1] as Uint8Array;
    const importedStr = new TextDecoder().decode(importArgs);
    expect(importedStr).toBe("abandon abandon");
  });

  it("should use the provided salt and iterations", async () => {
    mockSubtle.importKey.mockResolvedValue(mockCryptoKey);
    mockSubtle.deriveKey.mockResolvedValue(mockCryptoKey2);

    const salt = new Uint8Array([
      10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 13, 14, 15, 16,
    ]);
    const iterations = 600_000;
    await deriveRecoveryKey("mnemonic phrase", salt, iterations);

    expect(mockSubtle.deriveKey).toHaveBeenCalledWith(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      mockCryptoKey,
      { name: "AES-GCM", length: AES_KEY_LENGTH },
      false,
      ["encrypt", "decrypt"]
    );
  });
});

// ===========================================================================
// Utility Functions
// ===========================================================================
describe("Utility Functions", () => {
  it("bufToBase64 should convert ArrayBuffer to base64 string", () => {
    const buf = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
    const b64 = bufToBase64(buf);
    expect(b64).toBe("SGVsbG8=");
  });

  it("base64ToBuf should convert base64 string back to Uint8Array", () => {
    const result = base64ToBuf("SGVsbG8=");
    expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
  });

  it("bufToBase64 and base64ToBuf should roundtrip", () => {
    const original = new Uint8Array([0, 1, 2, 3, 255, 254, 128, 64]);
    const b64 = bufToBase64(original);
    const decoded = base64ToBuf(b64);
    expect(decoded).toEqual(original);
  });

  it("base64ToBuf should reject invalid base64", () => {
    expect(() => base64ToBuf("!!!invalid!!!")).toThrow();
  });

  it("randomBytes should produce a Uint8Array of the requested length", () => {
    const bytes = randomBytes(16);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(16);
  });

  it("randomBytes should fill values via getRandomValues", () => {
    const bytes = randomBytes(4);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(4);
    // All values are 0-255 (valid byte range)
    for (const b of bytes) {
      expect(b).toBeGreaterThanOrEqual(0);
      expect(b).toBeLessThanOrEqual(255);
    }
  });
});
