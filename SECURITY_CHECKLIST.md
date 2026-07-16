# Security Checklist — Zero-Knowledge Vault

A 120-point verification list. Each item must be answerable with ✓ (verified),
✗ (failed), or N/A (not applicable, with justification).

Auditor: __________________  Date: ____________  Commit: ____________

---

## A. Cryptographic Core (1-20)

- [ ] A1. Master password never leaves the client.
- [ ] A2. Master key is derived with Argon2id (m≥64 MiB, t≥3, p≥1) when WebAssembly is available.
- [ ] A3. PBKDF2 fallback uses ≥ 600,000 iterations of SHA-256.
- [ ] A4. The KDF algorithm name reported to the server matches what was actually used (no silent fallback).
- [ ] A5. Vault key is 256-bit, generated with `crypto.subtle.generateKey` or `crypto.getRandomValues`.
- [ ] A6. Vault key at rest is wrapped with AES-GCM (or RSA-OAEP for device share).
- [ ] A7. AES-GCM IVs are 96-bit and unique per encryption (random or counter, never zero).
- [ ] A8. AES-GCM ciphertext includes the IV; decryption rejects IVs shorter than 96 bits.
- [ ] A9. RSA key pairs are 2048-bit minimum; OAEP with SHA-256.
- [ ] A10. ECDH uses P-256 or stronger (P-384, P-521).
- [ ] A11. ECDSA signatures are over SHA-256 hashes, not raw messages.
- [ ] A12. `crypto.subtle.deriveKey` uses HKDF-SHA256 for subkey derivation (audit, device, share keys).
- [ ] A13. ML-KEM-768 is wired to the active share/decrypt flow, not a dead interface.
- [ ] A14. Hybrid KEM combines ML-KEM + classical ECDH, not ML-KEM alone.
- [ ] A15. `Math.random()` is never used for any security-relevant purpose.
- [ ] A16. MD5, SHA-1, AES-CBC, AES-ECB, DES, 3DES, RC4 are absent from source.
- [ ] A17. `crypto.subtle.decrypt` server-side calls are limited to non-secret values (audit metadata).
- [ ] A18. `crypto.subtle.deriveKey` is never called server-side.
- [ ] A19. Memory zeroing (`clearCryptoKeyRef`, `zeroBuffer`) is called for every transient key material.
- [ ] A20. `FinalizationRegistry` is registered for CryptoKey + KeyPair fallback GC.

## B. Authentication (21-35)

- [ ] B21. Registration derives and stores only the verifier (wrapped vault key + public keys).
- [ ] B22. Login uses decoy responses for unknown users to prevent enumeration.
- [ ] B23. Login rate limit: ≤ 5 attempts per IP per 5 minutes, with exponential backoff.
- [ ] B24. Session tokens are HS256-signed with ≥ 32-byte secret from env var.
- [ ] B25. Session tokens include `jti` (unique ID) for revocation.
- [ ] B26. Logout adds `jti` to Redis blacklist with TTL equal to token lifetime.
- [ ] B27. Redis blacklist failure is fail-open (token revocation) with logged alert — never locks out users.
- [ ] B28. Password reset tokens are single-use, 15-minute TTL, bound to user id.
- [ ] B29. Email verification is required before first secret creation.
- [ ] B30. WebAuthn registration verifies the attestation format and challenge.
- [ ] B31. WebAuthn login verifies the signature, challenge, origin, and RP ID.
- [ ] B32. SSO (OIDC) uses PKCE flow; `state` and `nonce` are validated.
- [ ] B33. SSO account linking requires re-authentication of the local account.
- [ ] B34. Failed login attempts are logged in `AuditLog` with IP, user agent, and reason.
- [ ] B35. Account lockout after 10 failed attempts (unlocked by admin or email reset).

## C. Authorization (36-50)

- [ ] C36. Every API route enforces authentication via `getSession()` middleware.
- [ ] C37. Every secret read verifies `secret.ownerId === session.user.id` (or shared with user).
- [ ] C38. Team vault access checks `TeamVaultMember.role` for read/write/admin.
- [ ] C39. Admin endpoints (`/api/admin/*`) check `user.role === 'ADMIN'`.
- [ ] C40. SCIM endpoints require a valid SCIM bearer token (separate from session tokens).
- [ ] C41. One-time share tokens are single-use, with TTL ≤ 24 hours.
- [ ] C42. Secret rotation requires the owner or admin — never a viewer.
- [ ] C43. Break-glass (dual-control) requires two distinct admins to approve.
- [ ] C44. API keys are scoped (read-only, read-write, admin) and revocable.
- [ ] C45. API key hash (SHA-256) is stored; the raw key is shown only once at creation.
- [ ] C46. Resource IDs in URLs are validated against the session user before fetch.
- [ ] C47. Bulk operations (delete, share) require per-item authorization check.
- [ ] C48. Audit log reads are restricted to the user's own logs + admins.
- [ ] C49. GraphQL/REST schema does not expose internal user IDs in responses (use opaque IDs).
- [ ] C50. No IDOR: every object fetch checks ownership even if the ID is in the URL.

## D. Input Validation (51-60)

- [ ] D51. Every API route body is validated with a Zod schema.
- [ ] D52. Every API route query string is validated with a Zod schema.
- [ ] D53. File uploads (if any) validate MIME type, size, and magic bytes.
- [ ] D54. Email validation rejects disposable domains (mailinator, guerrillamail, etc.) at signup.
- [ ] D55. Password validation: ≥ 12 chars, ≥ 3 of 4 character classes, zxcvbn score ≥ 3.
- [ ] D56. URL validation rejects `javascript:`, `data:`, `file:` schemes.
- [ ] D57. HTML rendering sanitizes with DOMPurify before `dangerouslySetInnerHTML`.
- [ ] D58. No `dangerouslySetInnerHTML` is used for user-provided content.
- [ ] D59. JSON responses set `Content-Type: application/json; charset=utf-8`.
- [ ] D60. No SQL string concatenation in raw queries — Prisma `$queryRaw` with parameters only.

## E. Transport & Headers (61-70)

- [ ] E61. HTTPS is enforced in production (HSTS header, 1 year, includeSubDomains, preload).
- [ ] E62. `X-Content-Type-Options: nosniff` set on all responses.
- [ ] E63. `X-Frame-Options: DENY` or `frame-ancestors 'none'` in CSP.
- [ ] E64. `Referrer-Policy: strict-origin-when-cross-origin`.
- [ ] E65. `Permissions-Policy` restricts camera, microphone, geolocation, payment.
- [ ] E66. CSP includes `default-src 'self'`, `script-src 'self'`, `connect-src 'self'`.
- [ ] E67. No `unsafe-inline` in CSP for scripts (use nonces or hashes).
- [ ] E68. Cookies have `Secure`, `HttpOnly`, `SameSite=Strict` (or `Lax` for SSO).
- [ ] E69. CORS `Access-Control-Allow-Origin` is an explicit allowlist, never `*`.
- [ ] E70. WebSocket origin is validated on connection.

## F. Supply Chain (71-80)

- [ ] F71. `bun install` runs with `--frozen-lockfile` in CI.
- [ ] F72. `bun audit` runs in CI; HIGH/CRITICAL findings fail the build.
- [ ] F73. Snyk action runs on every PR (with `SNYK_TOKEN` secret).
- [ ] F74. Trivy scans the Docker image; HIGH/CRITICAL findings fail the build (or are triaged).
- [ ] F75. Trivy scans Terraform and Helm for misconfigurations.
- [ ] F76. gitleaks scans full git history; baseline covers pre-existing secrets.
- [ ] F77. SBOM (CycloneDX) is generated on every release and uploaded as artifact.
- [ ] F78. License compliance check fails on GPL-3.0, AGPL-3.0, Unlicensed.
- [ ] F79. Dependabot is enabled for npm and GitHub Actions.
- [ ] F80. No `postinstall` scripts from untrusted packages (verify with `bun pm pack`).

## G. Data at Rest (81-90)

- [ ] G81. Database connection uses TLS (`?sslmode=require` or equivalent).
- [ ] G82. Database credentials are in env vars, not in the Prisma schema URL.
- [ ] G83. Database backups are encrypted with a key not stored alongside the backup.
- [ ] G84. Redis requires AUTH password and runs with `requirepass` + TLS.
- [ ] G85. S3 / object storage buckets are private with SSE-KMS.
- [ ] G86. Audit log entries are hash-chained (each entry references previous hash).
- [ ] G87. Audit log tamper detection runs on a schedule and alerts on mismatch.
- [ ] G88. PII columns (email) are stored hashed if used only for lookup; otherwise encrypted at column level.
- [ ] G89. GDPR Art. 17 (right to erasure) is implemented via crypto-shredding (destroy wrapped vault key).
- [ ] G90. GDPR Art. 20 (data portability) is implemented via `GET /api/gdpr/export`.

## H. Operations (91-100)

- [ ] H91. Logs do not contain `password`, `masterKey`, `token`, `secret`, `apiKey` substrings.
- [ ] H92. Error responses to clients do not leak stack traces (generic message + correlation ID).
- [ ] H93. OpenTelemetry traces do not include request bodies for sensitive endpoints.
- [ ] H94. Prometheus metrics do not include user IDs or secret IDs as labels.
- [ ] H95. Docker container runs as non-root user (`USER nextjs`).
- [ ] H96. Docker container uses a read-only root filesystem (`--read-only`).
- [ ] H97. Docker container drops ALL capabilities (`--cap-drop=ALL`).
- [ ] H98. Kubernetes pod uses `runAsNonRoot: true`, `readOnlyRootFilesystem: true`.
- [ ] H99. Kubernetes network policy denies egress except to DB, Redis, and required APIs.
- [ ] H100. Backups are tested by restoring into a staging database monthly.

## I. Compliance & Process (101-110)

- [ ] I101. SOC 2 controls mapped to specific code paths (documented in `docs/compliance/`).
- [ ] I102. GDPR data flow diagram matches the actual code paths.
- [ ] I103. Incident response runbook exists in `docs/runbooks/incident.md`.
- [ ] I104. On-call rotation and escalation policy documented.
- [ ] I105. Penetration test report from the last 12 months is on file.
- [ ] I106. Bug bounty or responsible disclosure policy is in `SECURITY.md`.
- [ ] I107. Crypto library versions are pinned and monitored for advisories.
- [ ] I108. Key rotation procedure documented; reminders scheduled quarterly.
- [ ] I109. Disaster recovery RTO/RPO defined; tested annually.
- [ ] I110. Change management: every PR to `main` requires 1 review approval.

## J. UX Security (111-120)

- [ ] J111. Password strength meter uses zxcvbn (real entropy, not length check).
- [ ] J112. Auto-lock after 5 minutes of inactivity (configurable, default 5 min).
- [ ] J113. Clipboard is cleared 30 seconds after copy (configurable).
- [ ] J114. Sensitive fields (passwords) use `autocomplete="off"` and `type="password"`.
- [ ] J115. BIP-39 recovery phrase display requires user click-to-reveal (no auto-render).
- [ ] J116. BIP-39 recovery phrase entry uses a separate component with no autocorrect/autofill.
- [ ] J117. Travel mode hides sensitive vaults (server-side flag, client-side filter).
- [ ] J118. Failed unlock attempts on the client are throttled locally (10/s hard limit).
- [ ] J119. Browser extension connects only to the configured origin.
- [ ] J120. Browser extension context menu requires unlocking the vault first.

---

## Scoring

| Range          | Verdict                                                    |
|----------------|------------------------------------------------------------|
| 110-120 ✓      | Production-ready for security-sensitive deployment.        |
| 90-109 ✓       | Security-hardened; remediate ✗ items in next sprint.       |
| 70-89 ✓        | Pre-audit state; remediate CRITICAL/HIGH ✗ before launch.  |
| < 70 ✓         | Not ready; do not deploy to production.                    |

Every ✗ must have a tracked issue with a remediation owner and target date.
