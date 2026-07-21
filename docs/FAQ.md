# FAQ — Due Diligence Technical
Q: Can the server decrypt my secrets? A: No. Server only stores AES-256-GCM ciphertext.
Q: What if server is compromised? A: Attacker gets blobs + public keys. Argon2id prevents brute-force.
Q: Is post-quantum real? A: Yes, ML-KEM-768 (NIST FIPS 203) in active share flow.
Q: Lost master password? A: BIP-39 24-word recovery phrase (256-bit entropy).
Q: Audit log tamper-proof? A: SHA-256 hash chain, verifiable via /api/audit-logs/verify.
Q: Known limitations? A: See ARCHITECTURE.md section 7.
Q: Multi-device? A: ECDH P-256 key exchange. Server never sees shared key.
Q: CSP? A: default-src 'self'; frame-ancestors 'none'; plus COOP/COEP/CORP.
