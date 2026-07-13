/**
 * test-crypto-roundtrip.ts — Unit tests for crypto primitives.
 * Run: bun scripts/tests/test-crypto-roundtrip.ts
 */
import {
  generateAesKey, aesEncrypt, aesDecrypt,
  exportAesKeyRaw, importAesKeyRaw,
  generateRsaKeyPair, exportPublicKeyJwk, importPublicKeyJwk,
  exportPrivateKeyJwk, importPrivateKeyJwk,
  wrapAesKeyWithRsaPublicKey, unwrapAesKeyWithRsaPrivateKey,
  generateEcdhKeyPair, deriveEcdhSharedAesKey,
  generateRecoveryMnemonic, validateRecoveryMnemonic, deriveRecoveryKey,
  constantTimeFingerprintCompare, publicKeyFingerprint,
  encryptNewSecret, decryptSecret,
} from "../../src/lib/crypto-client";

let passed = 0, failed = 0;
function assert(cond: boolean, msg: string) {
  if (cond) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.error(`  ✗ ${msg}`); }
}

console.log("\n=== AES-256-GCM Round-Trip ===");
{
  const key = await generateAesKey();
  const plaintext = "secret content 12345";
  const { ciphertext, iv } = await aesEncrypt(key, plaintext);
  const decrypted = await aesDecrypt(key, ciphertext, iv);
  assert(decrypted === plaintext, "AES encrypt/decrypt round-trip");
  assert(ciphertext !== plaintext, "AES ciphertext differs from plaintext");
  assert(iv.length > 0, "AES IV is non-empty");
}

console.log("\n=== RSA-OAEP Wrap/Unwrap ===");
{
  const rsaPair = await generateRsaKeyPair();
  const aesKey = await generateAesKey();
  const wrapped = await wrapAesKeyWithRsaPublicKey(aesKey, rsaPair.publicKey);
  const unwrapped = await unwrapAesKeyWithRsaPrivateKey(wrapped, rsaPair.privateKey);
  assert(!!unwrapped, "RSA wrap/unwrap produces valid CryptoKey");
  const raw1 = await exportAesKeyRaw(aesKey);
  const raw2 = await exportAesKeyRaw(unwrapped);
  assert(raw1.byteLength === raw2.byteLength, "Unwrapped AES key has same length");
}

console.log("\n=== ECDH Shared Secret ===");
{
  const alicePair = await generateEcdhKeyPair();
  const bobPair = await generateEcdhKeyPair();
  const aliceShared = await deriveEcdhSharedAesKey(alicePair.privateKey, bobPair.publicKey);
  const bobShared = await deriveEcdhSharedAesKey(bobPair.privateKey, alicePair.publicKey);
  const plaintext = "ecdh test";
  const { ciphertext, iv } = await aesEncrypt(aliceShared, plaintext);
  const decrypted = await aesDecrypt(bobShared, ciphertext, iv);
  assert(decrypted === plaintext, "ECDH shared secret produces same key on both sides");
}

console.log("\n=== BIP-39 Recovery ===");
{
  const { mnemonic } = await generateRecoveryMnemonic();
  assert(mnemonic.split(" ").length === 24, "BIP-39 generates 24 words");
  const valid = await validateRecoveryMnemonic(mnemonic);
  assert(valid, "BIP-39 mnemonic validates");
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const key = await deriveRecoveryKey(mnemonic, salt);
  assert(!!key, "BIP-39 derives AES key from mnemonic");
}

console.log("\n=== Constant-Time Fingerprint Compare ===");
{
  assert(constantTimeFingerprintCompare("abc", "abc"), "Equal strings match");
  assert(!constantTimeFingerprintCompare("abc", "abd"), "Different strings don't match");
  assert(!constantTimeFingerprintCompare("abc", "ab"), "Different lengths don't match");
}

console.log("\n=== Full Secret Encrypt/Decrypt ===");
{
  const rsaPair = await generateRsaKeyPair();
  const { encryptedTitle, titleIv, encryptedData, dataIv, wrappedKeyForOwner } = await encryptNewSecret("My Secret", "top value", rsaPair.publicKey);
  const { title, content } = await decryptSecret(wrappedKeyForOwner, encryptedTitle, titleIv, encryptedData, dataIv, rsaPair.privateKey, null);
  assert(title === "My Secret", "Secret title round-trips");
  assert(content === "top value", "Secret content round-trips");
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
