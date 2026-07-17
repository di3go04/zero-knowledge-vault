# @zk-vault/crypto

Zero-Knowledge Vault crypto module — Web Crypto API primitives for end-to-end encrypted password management.

## Installation

```bash
npm install @zk-vault/crypto
# or
bun add @zk-vault/crypto
```

## Usage

```typescript
import {
  // KDF
  deriveMasterKey,
  argon2DefaultParams,
  pbkdf2LegacyParams,
  // AES-GCM
  aesEncrypt,
  aesDecrypt,
  // RSA-OAEP
  generateRsaKeyPair,
  wrapAesKeyWithRsaPublicKey,
  unwrapAesKeyWithRsaPrivateKey,
  // ECDH multi-device
  generateEcdhKeyPair,
  deriveEcdhSharedAesKey,
  // HKDF subkeys
  deriveSubKey,
  // Memory zeroing
  zeroBuffer,
  clearCryptoKeyRef,
  // Recovery (BIP-39)
  generateRecoveryMnemonic,
  validateRecoveryMnemonic,
  // High-level flows
  performRegistration,
  performLogin,
  encryptNewSecret,
  decryptSecret,
} from "@zk-vault/crypto";

// 1. Register a new user
const kdfParams = argon2DefaultParams(crypto.getRandomValues(new Uint8Array(16)));
const masterKey = await deriveMasterKey("user-password", kdfParams);
const rsaPair = await generateRsaKeyPair();
// ... encrypt private key with masterKey, send to server ...

// 2. Encrypt a secret
const encrypted = await encryptNewSecret(masterKey);
// store encrypted.encryptedTitle + encrypted.encryptedData on server

// 3. Multi-device enrollment via ECDH
const pairB = await generateEcdhKeyPair();
const sharedKey = await deriveEcdhSharedAesKey(pairB.privateKey, peerPublicKey);
// ... wrap user's private key with sharedKey, send to device B ...

// 4. Derive independent subkeys via HKDF
const auditKey = await deriveSubKey(masterKey, "audit");
const deviceKey = await deriveSubKey(masterKey, "device");
// auditKey ≠ deviceKey — cryptographically isolated
```

## Crypto stack

| Layer | Algorithm | Use |
|-------|-----------|-----|
| KDF | Argon2id (m=64MiB, t=3, p=4) | Derive masterKey from password |
| KDF fallback | PBKDF2-SHA256 (600k iter) | If Argon2id unavailable |
| Subkey | HKDF-SHA256 | audit, device, share, metadata |
| Symmetric | AES-256-GCM (96-bit IV, AAD) | Encrypt blobs |
| Wrap | RSA-OAEP 2048 (SHA-256) | Wrap AES keys for recipients |
| Sign | RSA-PSS 2048 (SHA-256, salt=32) | Proof-of-Possession |
| Multi-device | ECDH P-256 | Shared key between devices |
| Enrollment | ECDSA P-256 (SHA-256) | Challenge-response |
| Post-quantum | ML-KEM-768 | Hybrid KEM with ECDH |
| Recovery | BIP-39 (24 words, 256 bits) | Backup of private key |

## API

See `src/index.ts` for the full list of exports.

## License

MIT
