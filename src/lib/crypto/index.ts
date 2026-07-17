/**
 * =====================================================================
 * Zero-Knowledge Vault — Crypto module
 * =====================================================================
 *
 * Public API for all cryptographic operations.
 *
 * Design principles:
 *  - All encryption happens client-side via Web Crypto API.
 *  - The server is "crypto-blind": it never receives master passwords,
 *    master keys, private keys (in plaintext), or plaintext secrets.
 *  - Memory zeroing is enforced for every transient CryptoKey.
 *
 * Module structure:
 *  - `client.ts`  — client-side crypto (KDF, AES-GCM, RSA-OAEP, ECDH, ECDSA)
 *  - `server.ts`  — server-side verification (signatures, PoP, decoy)
 *  - `rotation.ts`— master password rotation flow
 *  - `memory.ts`  — memory zeroing utilities
 *  - `hkdf.ts`    — HKDF-SHA256 subkey derivation
 *  - `pq-kem.ts`  — ML-KEM-768 post-quantum KEM (hybrid with ECDH)
 *  - `argon2-worker.ts` — Web Worker for Argon2id (hash-wasm)
 * =====================================================================
 */

// ===== Client-side crypto =====
export {
  // Types
  type KdfAlgorithm,
  type KdfParams,
  type RegistrationArtifacts,
  type LoginArtifacts,
  type SecretArtifacts,
  type RotationArtifacts,
  type EncryptedPrivateKey,
  type AuditCategory,
  // Constants
  RECOVERY_ITERATIONS,
  // Encoding
  bufToBase64,
  base64ToBuf,
  randomBytes,
  normalizePassword,
  canonicalJwkString,
  publicKeyFingerprint,
  cachedPublicKeyFingerprint,
  constantTimeFingerprintCompare,
  generateEnrollCode,
  // KDF
  deriveMasterKey,
  deriveMasterKeyRaw,
  deriveAuditKey,
  deriveRecoveryKey,
  argon2DefaultParams,
  pbkdf2LegacyParams,
  // AES-GCM
  aesEncrypt,
  aesDecrypt,
  generateAesKey,
  exportAesKeyRaw,
  importAesKeyRaw,
  // RSA-OAEP
  generateRsaKeyPair,
  exportPublicKeyJwk,
  exportPrivateKeyJwk,
  importPublicKeyJwk,
  importPrivateKeyJwk,
  encryptPrivateKey,
  decryptPrivateKey,
  encryptPrivateKeyForRecovery,
  decryptPrivateKeyForRecovery,
  wrapAesKeyWithRsaPublicKey,
  unwrapAesKeyWithRsaPrivateKey,
  // PoP / signatures
  buildPopMessage,
  signPop,
  verifyPop,
  // Audit log crypto
  encryptAuditEvent,
  decryptAuditEvent,
  // High-level flows
  performRegistration,
  performLogin,
  performPasswordRotation,
  encryptNewSecret,
  decryptSecret,
  shareSecretWithRecipient,
  // Recovery (BIP-39)
  generateRecoveryMnemonic,
  validateRecoveryMnemonic,
  // ECDH multi-device
  generateEcdhKeyPair,
  exportEcdhPublicKeyJwk,
  importEcdhPublicKeyJwk,
  importEcdhPrivateKeyJwk,
  deriveEcdhSharedAesKey,
  wrapPrivateKeyForDevice,
  unwrapPrivateKeyForDevice,
  // ECDSA challenge-response
  importEcdhPrivateKeyForSigning,
  importEcdhPublicKeyForVerifying,
  signChallenge,
  verifyChallenge,
} from "./client";

// ===== Server-side crypto (verification only) =====
// IMPORTANT: server.ts uses node:crypto and must only be imported from
// API routes / server components. It is NOT re-exported from this index
// to avoid pulling node:crypto into client bundles.
//
// Server code should import directly from "@/lib/crypto/server".

// ===== Memory zeroing =====
export {
  zeroBuffer,
  clearCryptoKeyRef,
  clearKeyPairRef,
  zeroString,
  trackBuffer,
  createTrackedArray,
  secureZero,
} from "./memory";

// ===== HKDF subkey derivation =====
export {
  deriveSubKey,
  deriveAllSubKeys,
  type SubKeyType,
} from "./hkdf";

// ===== Key rotation =====
export {
  rewrapSingleKey,
  rewrapAllKeys,
  type KeyRotationParams,
  type KeyRotationResult,
} from "./rotation";

// ===== Post-quantum KEM (ML-KEM-768) =====
export {
  MLKEM768KEM,
  getActiveKEM,
  isKemWrappedKey,
} from "./pq-kem";

// ===== Hash chain (tamper-evident audit logs) =====
export {
  sha256Hex,
  computeLogHash,
  verifyChain,
} from "./hash-chain";
