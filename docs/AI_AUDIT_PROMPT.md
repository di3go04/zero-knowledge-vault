# AI Audit Prompt — Zero-Knowledge Vault

This file is a ready-to-use prompt for any LLM-based code reviewer (Claude,
GPT-4/5, Gemini, local models) to audit this repository and produce a
structured list of 30+ concrete improvements.

## How to use

1. Open a new chat with any capable LLM (≥ 200K context recommended).
2. Paste the prompt below.
3. Attach the following files (or paste their contents):
   - `AUDITING.md`
   - `SECURITY_CHECKLIST.md`
   - `ARCHITECTURE.md`
   - `audit-reports/latest.md` (run `bun run audit:full` first)
   - `src/lib/crypto-client.ts`
   - `src/lib/crypto-server.ts`
   - `src/lib/pq-kem-real.ts`
   - `prisma/schema.prisma`
   - Any 5 files from `src/app/api/`
4. The model will return a Markdown table with 30+ findings.
5. Triage and file GitHub Issues for the accepted findings.

---

## Prompt (copy everything below this line)

```
You are a senior security engineer auditing a Zero-Knowledge Password Manager
written in TypeScript / Next.js 16. The repository implements end-to-end
encryption using Web Crypto API: Argon2id KDF, AES-256-GCM, RSA-OAEP 2048,
ECDH P-256, ECDSA P-256, and ML-KEM-768 for post-quantum hybrid key exchange.

Your job is to produce a structured audit report with AT LEAST 30 concrete,
actionable findings. Do not pad the list with cosmetic issues. If you cannot
find 30 real findings, say so explicitly and recommend monitoring /
hardening work instead.

# Threat model

- The server is a "crypto-blind store": it must NEVER receive the master
  password, the master key, the vault key in plaintext, the private keys,
  or the plaintext secret content.
- The client (browser) is trusted for crypto; the server is trusted only for
  storage, routing, and audit logging.
- Adversaries: passive network, active network (MITM), malicious server
  operator, compromised client, compromised admin, post-quantum adversary
  (harvest-now-decrypt-later).

# What to audit

1. Cryptographic correctness (KDF parameters, IV uniqueness, key wrapping,
   signature verification, ML-KEM hybrid wiring).
2. Zero-knowledge property (any server-side access to plaintext secrets,
   master password, or private keys is a CRITICAL finding).
3. Authentication & session management (token format, revocation, rate
   limiting, lockout, SSO/ OIDC / WebAuthn flows).
4. Authorization (per-row ownership checks, IDOR, RBAC, team vault access).
5. Input validation (Zod schemas, SQL/NoSQL injection, SSRF, open redirect,
   path traversal, prototype pollution).
6. Transport security (HSTS, CSP, cookies, CORS, WebSocket origin).
7. Supply chain (dependency vulnerabilities, license compliance, SBOM).
8. Data at rest (DB TLS, Redis auth, S3 encryption, audit log integrity).
9. Operations (logging hygiene, error leakage, Docker hardening, K8s pod
   security, network policies).
10. UX security (clipboard auto-clear, auto-lock, recovery phrase display).
11. Compliance (GDPR Art. 17/20, SOC 2 controls).
12. Code quality (cyclomatic complexity, dead code, type coverage).

# Output format

Produce a single Markdown table with exactly these columns:

| # | Severity | Category | File:Line | Finding | Recommendation | Effort |

Rules:
- Severity ∈ { CRITICAL, HIGH, MEDIUM, LOW, INFO }
- Category ∈ { crypto, auth, authz, injection, zk-property, secret-leak,
  supply-chain, i18n, a11y, performance, reliability, compliance, docs }
- File:Line must be a clickable path like `src/lib/crypto-client.ts:142`.
- Finding: 1-2 sentences, specific to a code location.
- Recommendation: 1-2 sentences, with a code sketch when useful.
- Effort ∈ { S (<1h), M (1-4h), L (4-16h), XL (>16h) }

# Constraints

- Do NOT recommend generic "add tests" without specifying the test.
- Do NOT recommend "add logging" without specifying what to log and what to
  redact.
- Do NOT consolidate different findings in different files into one row —
  each location gets its own row.
- Do NOT skip a finding because the audit report already mentions it —
  restate it in your own words with a concrete location.
- DO flag anything that would fail the SECURITY_CHECKLIST.md items.
- DO flag any drift between ARCHITECTURE.md and the actual code.
- DO flag any crypto primitive used outside the approved list:
  AES-GCM, RSA-OAEP, RSA-PSS, ECDH P-256, ECDSA P-256, HKDF-SHA256,
  PBKDF2 (≥600K iter), Argon2id (m≥64MiB, t≥3, p≥1), ML-KEM-768.

# After the table

Append a section titled "Verdict" with:
- Overall security posture (1 paragraph).
- Top 3 risks to remediate first.
- Recommended audit cadence (quarterly / annual / per-release).

Begin your audit now. Read every attached file carefully before producing
the findings table. Do not invent code paths that are not in the attached
files.
```

---

## Expected output (example structure)

The LLM should produce something like:

| # | Severity | Category | File:Line | Finding | Recommendation | Effort |
|---|----------|----------|-----------|---------|----------------|--------|
| 1 | HIGH | crypto | src/lib/crypto-client.ts:142 | IV derived from timestamp | Use `crypto.getRandomValues(new Uint8Array(12))` | S |
| 2 | MEDIUM | auth | src/app/api/auth/login/route.ts:88 | No IP-based rate limit on login | Add `rateLimit('login', ip)` middleware | M |
| ... | ... | ... | ... | ... | ... | ... |

(30+ rows)

## Verdict

(1 paragraph summary + top 3 risks + cadence)

---

## Post-audit workflow

1. Copy the LLM output into `audit-reports/llm-<model>-<date>.md`.
2. Triage each row:
   - Accept → file GitHub Issue with `audit-finding` label.
   - Reject → mark in the report with reason.
3. Remediate accepted findings in priority order.
4. Re-run `bun run audit:full` and re-issue the AI prompt with the updated
   report. Iterate until no CRITICAL/HIGH findings remain.
