# Zero-Knowledge Vault — Architecture

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| DB compromised | All data is AES-256-GCM encrypted blobs. No plaintext keys, secrets, or passwords stored. Argon2id KDF makes offline brute-force impractical (64 MiB per attempt). |
| MITM active | TOFU fingerprint verification (SHA-256 of canonicalized JWK). HTTPS required. PoP (RSA-PSS) at registration prevents key substitution. |
| Malicious server | Server never receives master password, masterKey, or private keys. Login decoy prevents email enumeration. Audit logs encrypted client-side — server cannot read them. |
| Brute force | Rate limiting on login (5/15min), enroll/verify (5/1min), recovery (3/hour). Argon2id memory-hard KDF. Session timeout (15 min inactivity). |
| Quantum computer | ML-KEM-768 wired to active share/decrypt flow. Hybrid KEM wrap: ML-KEM encapsulate + AES-GCM encrypt. Forward secrecy via ephemeral ECDH. |
| Device loss | Device revocation endpoint. Password rotation re-encrypts private key with new masterKey. |
| Insider threat | Crypto-shredding: account deletion overwrites all blobs with garbage before deletion. Audit logs tamper-evident (hash chaining). |

## Cryptographic Stack

| Algorithm | Use | Parameters |
|-----------|-----|-----------|
| Argon2id | KDF (password → masterKey) | m=64 MiB, t=3, p=4, salt=16 bytes |
| PBKDF2-SHA256 | KDF fallback | 600,000 iterations |
| AES-256-GCM | Symmetric encryption | IV=12 bytes, tag=16 bytes |
| RSA-OAEP 2048 | Key wrapping (legacy) | SHA-256 |
| RSA-PSS 2048 | Proof-of-Possession | SHA-256, salt=32 |
| ML-KEM-768 | Post-quantum key wrapping | FIPS 203 |
| ECDH P-256 | Multi-device shared secret | NIST P-256 |
| ECDSA P-256 | Challenge-response | SHA-256 |
| BIP-39 | Recovery key | 24 words, 256-bit entropy |
| Shamir's SS | Distributed recovery | 5 shares, 3 threshold |
| HKDF-SHA256 | Subkey derivation | audit-key, device-key, share-key |

## Multi-Device Enrollment Flow (ECDH + ECDSA)

```
Device B (new)                    Server                    Device A (authed)
     |                              |                              |
  1. Generate ECDH P-256 keypair   |                              |
  2. POST /enroll/init ----->      |                              |
     {email, publicKeyECDH}        |                              |
     <----- {enrollCode, deviceId} |                              |
     |                              |                              |
  3. Show enrollCode to user       |                              |
     |                              |     4. GET /enroll/lookup -->|
     |                              |     <--- {publicKeyECDH} ----|
     |                              |                              |
     |                              |  5. Generate ephemeral ECDH  |
     |                              |     Derive shared secret     |
     |                              |     Wrap privateKey RSA      |
     |                              |                              |
     |                              |  6. POST /enroll/complete -->|
     |                              |     {wrappedPrivateKey,      |
     |                              |      enrollerPublicKeyECDH}  |
     |                              |                              |
  7. POST /enroll/poll ------>     |                              |
     {deviceId}                    |                              |
     <----- {challenge (32 bytes)} |                              |
     |                              |                              |
  8. Sign challenge with ECDSA     |                              |
     POST /enroll/poll/verify -->  |                              |
     {challenge, signature}        |                              |
     <----- {wrappedPrivateKey,    |                              |
     |        enrollerPublicKeyECDH}|                              |
     |                              |                              |
  9. Derive shared secret:         |                              |
     B.privateKey × A.publicKey    |                              |
 10. Unwrap privateKey RSA (AES)   |                              |
 11. Store in session → dashboard  |                              |
```

## Metadata in Clear vs Encrypted

| Field | In Clear | Encrypted | Notes |
|-------|----------|-----------|-------|
| User.email | ✓ | | Required for login, lookup |
| User.name | ✓ | | Display name |
| UserKeyMaterial.kdfSalt | ✓ | | Public, needed for KDF |
| UserKeyMaterial.publicKeyJwk | ✓ | | Public by definition |
| UserKeyMaterial.mlKemPublicKey | ✓ | | Public by definition |
| UserKeyMaterial.encryptedPrivateKeyJwk | | ✓ | AES-256-GCM with masterKey |
| UserKeyMaterial.encryptedMlKemPrivateKey | | ✓ | AES-256-GCM with masterKey |
| Secret.encryptedTitle | | ✓ | AES-256-GCM |
| Secret.encryptedData | | ✓ | AES-256-GCM |
| SecretKeyShare.wrappedSymmetricKey | | ✓ | RSA-OAEP or ML-KEM wrapped |
| AuditLog.encryptedEvent | | ✓ | AES-256-GCM with auditKey |
| AuditLog.eventCategory | ✓ | | For indexing only (auth/secret/share/device/recovery) |
| AuditLog.prevHash, logHash | ✓ | | Tamper-evidence chain |
| Device.publicKeyECDH | ✓ | | Public by definition |
| Device.enrollerPublicKeyECDH | ✓ | | Public by definition |
| Device.wrappedPrivateKeyForDevice | | ✓ | AES-256-GCM with ECDH shared secret |

## GDPR Compliance

| Article | Implementation |
|---------|---------------|
| Art. 17 (Right to erasure) | `DELETE /api/account/delete` — crypto-shredding: overwrites all encrypted blobs with garbage, then deletes all records |
| Art. 20 (Data portability) | `GET /api/account/export` — returns JSON with all encrypted data (client decrypts locally) |
| Art. 25 (Privacy by design) | Minimization: API responses only include necessary fields. Login decoy prevents enumeration. |
| Art. 32 (Security) | AES-256-GCM, Argon2id, TLS required, rate limiting, Redis blacklist |
| Art. 33 (Breach notification) | Audit logs with hash chaining detect tampering. No plaintext data to breach. |
