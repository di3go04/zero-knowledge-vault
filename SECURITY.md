# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Zero-Knowledge Vault:

1. **DO NOT** open a public GitHub issue.
2. Email: security@zk-vault.local (replace with real email)
3. Include: description, steps to reproduce, potential impact.
4. Response time: within 48 hours.
5. We will acknowledge receipt and provide a timeline for fix.

## Scope

- All endpoints under `/api/`
- Client-side crypto in `src/lib/crypto/`
- Authentication and session management
- Rate limiting and brute-force protection

## Out of Scope

- Vulnerabilities in third-party dependencies (report to upstream)
- Self-hosted deployments with misconfigured env vars
- Social engineering attacks

## Disclosure Policy

- We follow responsible disclosure.
- Fix will be released before public disclosure.
- Credit will be given to reporter (unless they prefer anonymity).

## Security Measures

- Zero-knowledge architecture (server never sees plaintext)
- Argon2id KDF (64 MiB, 3 iterations, 4 parallelism)
- AES-256-GCM with 96-bit random IVs
- RSA-OAEP 2048-bit for key wrapping
- ML-KEM-768 post-quantum hybrid
- Rate limiting on all sensitive endpoints
- CSP, HSTS, X-Frame-Options headers
- Pino logger with automatic secret redaction
