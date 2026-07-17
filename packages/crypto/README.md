# @zk-vault/crypto

Cryptographic primitives for the Zero-Knowledge Vault ecosystem.

## Features

- **AES-256-GCM** — Symmetric encryption/decryption
- **RSA-OAEP 2048-bit** — Asymmetric key wrapping
- **ECDH P-256** — Key exchange for multi-device sync
- **ECDSA P-256** — Challenge-response verification
- **Argon2id** — Memory-hard key derivation (WASM via hash-wasm)
- **PBKDF2** — Fallback KDF (600k iterations)
- **BIP-39** — Recovery phrase generation/validation
- **Memory zeroing** — Cryptographic cleanup utilities

## Usage

```typescript
import { encryptAesGcm, decryptAesGcm } from "@zk-vault/crypto";

const key = await generateAesKey();
const ciphertext = await encryptAesGcm(key, plaintext);
const decrypted = await decryptAesGcm(key, ciphertext);
```

## Security

All cryptographic operations use Web Crypto API when available,
with fallbacks for Node.js environments.
