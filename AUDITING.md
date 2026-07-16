# Auditing the Zero-Knowledge Vault

This document is the canonical guide for reviewing this codebase. It is written
for two audiences:

1. **Human reviewers** — security engineers, cryptography-literate developers,
   and auditors who want to verify the zero-knowledge property holds.
2. **AI reviewers** — any LLM (Claude, GPT, Gemini, local models) pointed at the
   repository to produce a structured list of improvements.

The goal: any reviewer, human or AI, should be able to produce a list of **30+
concrete, actionable improvements** after following this guide end-to-end.

---

## 0. What "audit" means here

We use the word *audit* in the engineering sense: a systematic review that
produces a finding list. This is **not** a formal third-party security audit
and does not produce a legally recognized certificate.

The audit covers six dimensions:

| # | Dimension                | Tool(s)                                      |
|---|--------------------------|----------------------------------------------|
| 1 | Static analysis (SAST)   | ESLint security, Semgrep, CodeQL             |
| 2 | Supply chain (SCA)       | bun audit, Snyk, Trivy, license-checker      |
| 3 | Secret scanning          | gitleaks                                     |
| 4 | Container & IaC scanning | Trivy (Docker, Terraform, Helm)              |
| 5 | Crypto-specific review   | `scripts/crypto-audit.mjs`                   |
| 6 | ZK-property verification | `scripts/zk-property-audit.mjs`              |

---

## 1. One-command audit

```bash
bun install
bun run audit:full
```

This runs every local analyzer and writes a single Markdown report to:

```
audit-reports/audit-<timestamp>.md
audit-reports/latest.md          # symlink
audit-reports/sarif-<timestamp>/ # machine-readable artifacts
```

Open `audit-reports/latest.md` and read top-to-bottom. The report contains:

- Dependency manifest and lockfile stats
- `bun audit` output
- ESLint output (security + no-unsanitized rules)
- TypeScript typecheck
- Semgrep findings (OWASP/CWE/crypto-misuse rules)
- Cyclomatic complexity report
- Dead-code detection (`ts-prune`)
- License compliance summary
- Source LOC statistics (by directory + top-20 largest files)
- Type-coverage percentage
- Prisma schema validation
- **Crypto implementation audit** (required primitives + forbidden patterns)
- API endpoint inventory (method, path, file)
- **Zero-knowledge property audit** (server-side forbidden variables)
- SBOM (CycloneDX)
- Git history hygiene (commits mentioning AI / scaffold / etc.)
- Documentation file inventory

---

## 2. Individual analyzers

Each analyzer can be run independently. Use these when iterating on a specific
class of finding.

```bash
# SAST
bun run lint                  # ESLint with security/no-unsanitized plugins
bun run semgrep               # Semgrep with custom rules in semgrep.yml

# Supply chain
bun run audit:deps            # bun audit (production, severity >= moderate)
bunx license-checker --production --summary

# Secrets
bun run gitleaks              # gitleaks with .gitleaks.toml config

# Crypto-specific
bun run audit:crypto          # scripts/crypto-audit.mjs

# Zero-knowledge property
bun run audit:zk              # scripts/zk-property-audit.mjs

# Code quality
bun run complexity            # cyclomatic complexity > 15
bun run deadcode              # ts-prune (unused exports)
bun run typecov               # type-coverage %

# SBOM
bun run sbom                  # CycloneDX 1.5 JSON to audit-reports/sbom.cdx.json
```

---

## 3. CI / GitHub Actions

The following workflows run automatically on every push to `main` and on every
pull request. Their results appear in the **Actions** tab and in the
**Security → Code scanning alerts** tab.

| Workflow                                            | File                                   | Purpose                                              |
|-----------------------------------------------------|----------------------------------------|------------------------------------------------------|
| `ci.yml`                                            | `.github/workflows/ci.yml`             | lint, typecheck, build, E2E (continue-on-error)      |
| `🔍 CodeQL SAST Analysis`                          | `.github/workflows/codeql.yml`         | GitHub CodeQL with security-and-quality query pack   |
| `🛡️ Supply Chain & Container Security`             | `.github/workflows/supply-chain.yml`   | Snyk, bun audit, Trivy (fs + Docker + IaC), licenses |
| `🔐 Secret Scanning (gitleaks)`                    | `.github/workflows/secrets.yml`        | gitleaks with commit history scanning                |

All workflows upload SARIF artifacts to GitHub's Security tab, so findings are
triaged alongside CodeQL results.

---

## 4. How to review the crypto core (manual)

The cryptographic core lives in `src/lib/crypto-client.ts` (client side) and
`src/lib/crypto-server.ts` (server side). The two files together implement the
zero-knowledge protocol. Read them in this order:

1. `src/lib/crypto-client.ts`
   - `deriveMasterKey()` — KDF (Argon2id via hash-wasm, fallback to PBKDF2)
   - `encryptVaultKey()` / `decryptVaultKey()` — AES-GCM with the derived key
   - `wrapVaultKeyForDevice()` / `unwrapVaultKeyForDevice()` — RSA-OAEP + ECDH
   - `encryptSecret()` / `decryptSecret()` — AES-GCM with random IV
   - `signChallenge()` / `verifyChallenge()` — ECDSA P-256
   - `clearCryptoKeyRef()`, `clearKeyPairRef()`, `zeroBuffer()` — memory zeroing
   - `shareSecret()` / `decryptShared()` — RSA-OAEP + ECDH hybrid

2. `src/lib/pq-kem-real.ts`
   - ML-KEM-768 encaps/decaps via `@noble/post-quantum`
   - Hybrid KEM: ML-KEM encapsulate → AES-GCM wrap → KEM+ciphertext sent

3. `src/lib/crypto-server.ts`
   - Server never sees master password, master key, or plaintext secret
   - Server performs only: signature verification, public key wrapping, audit

4. `prisma/schema.prisma`
   - Verify all `Secret` fields are ciphertext / wrapped keys
   - Verify `UserKeyMaterial` only stores public keys + wrapped private keys

5. `src/app/api/` — every `route.ts`
   - Confirm no `masterPassword` / `privateKey` / `decryptedSecret` parameters
   - Confirm Zod validation on every input

### Zero-knowledge property checklist

For each API endpoint, ask:

- [ ] Does the request body contain `masterPassword`? → **violation**
- [ ] Does the request body contain `privateKey` (raw JWK)? → **violation**
- [ ] Does the request body contain plaintext secret content? → **violation**
- [ ] Does the response body contain a decrypted secret? → **violation**
- [ ] Does the server call `crypto.subtle.decrypt` on user-supplied ciphertext?
      → verify the decrypted value is non-secret (e.g. audit metadata)
- [ ] Does the server call `crypto.subtle.deriveKey`? → **violation**
- [ ] Does the server log any of: `password`, `masterKey`, `token`, `secret`?
      → **violation**

The `audit:zk` script automates this check; the manual review confirms the
automated check is sound.

---

## 5. How to review the threat model

`ARCHITECTURE.md` contains the threat model. Read the following sections:

1. **Assets** — what we are protecting (master key, vault key, secrets, audit log)
2. **Trust boundaries** — client / server / DB / Redis / S3
3. **Adversary capabilities** — passive network, active network, malicious
   server, compromised client, compromised admin, post-quantum adversary
4. **Mitigations** — what each crypto primitive defends against

When proposing improvements, map each finding to an asset + adversary pair. A
finding that does not change the threat model is usually a quality issue, not
a security issue.

---

## 6. How an AI reviewer should produce 30+ improvements

### 6.1 Inputs

Feed the AI reviewer the following context:

1. This file (`AUDITING.md`)
2. `SECURITY_CHECKLIST.md`
3. `ARCHITECTURE.md`
4. The latest audit report: `audit-reports/latest.md`
5. The crypto core: `src/lib/crypto-client.ts`, `src/lib/crypto-server.ts`,
   `src/lib/pq-kem-real.ts`
6. The Prisma schema: `prisma/schema.prisma`
7. A representative sample of API routes (any 5)
8. The prompt from `docs/AI_AUDIT_PROMPT.md`

### 6.2 Output contract

The AI reviewer MUST output a Markdown table with exactly these columns:

| # | Severity | Category | File:Line | Finding | Recommendation | Effort |
|---|----------|----------|-----------|---------|----------------|--------|

- **Severity**: `CRITICAL` | `HIGH` | `MEDIUM` | `LOW` | `INFO`
- **Category**: `crypto` | `auth` | `authz` | `injection` | `zk-property` |
  `secret-leak` | `supply-chain` | `i18n` | `a11y` | `performance` |
  `reliability` | `compliance` | `docs`
- **File:Line**: clickable path, e.g. `src/lib/crypto-client.ts:142`
- **Finding**: 1-2 sentences describing the issue
- **Recommendation**: 1-2 sentences describing the fix, with a code sketch if
  useful
- **Effort**: `S` (< 1 hour) | `M` (1-4 hours) | `L` (4-16 hours) | `XL` (> 16 hours)

### 6.3 Minimum 30 findings

The reviewer must produce **at least 30** findings. If fewer than 30 concrete
findings can be produced after a thorough review, the reviewer must explicitly
state "the codebase is in a mature state" and produce a list of monitoring
and hardening recommendations instead.

The reviewer MUST NOT:

- Pad the list with cosmetic issues (whitespace, naming) unless they actively
  harm readability or hide a defect.
- Repeat the same finding for multiple files — consolidate.
- Recommend "add tests" without specifying which tests for which behavior.
- Recommend "add logging" without specifying what should be logged and what
  must be redacted.

### 6.4 Verification step

After the reviewer produces the 30 findings, the human maintainer should:

1. Triage by severity (CRITICAL → XL first)
2. File each accepted finding as a GitHub Issue with the `audit-finding` label
3. Remediate in priority order
4. Re-run `bun run audit:full` and confirm the report shows zero ERROR-severity
   findings before closing the audit cycle

---

## 7. Branch strategy for auditors

If you are an external auditor and do not have write access to `main`, the
recommended workflow is:

```bash
git clone https://github.com/di3go04/zero-knowledge-vault.git
cd zero-knowledge-vault
git checkout -b audit/<your-name>-<date>
bun install
bun run audit:full
# Read audit-reports/latest.md
# Make a copy: cp audit-reports/latest.md audit-reports/<your-name>.md
# Commit your findings:
git add audit-reports/<your-name>.md
git commit -m "audit: <your-name> review"
git push -u origin audit/<your-name>-<date>
# Open a PR titled "Audit: <your-name>"
```

The PR description should contain the 30+ findings table (section 6.2).

---

## 8. Source code branches

The `main` branch contains the full source. There is no separate `source`
branch — the entire repository is source-first. Build artifacts (`.next/`,
`dist/`) are gitignored.

If a reviewer wants a smaller surface area, they can review only:

```
src/lib/                   # crypto + protocol
src/app/api/               # all HTTP endpoints
prisma/schema.prisma       # data model
ARCHITECTURE.md            # threat model
SECURITY_CHECKLIST.md      # verification list
```

These ~10 files are sufficient to verify the zero-knowledge property.

---

## 9. FAQ

**Q: The CI says "CodeQL upload failed". Why?**
A: CodeQL uploads require the `security-events: write` permission. The workflow
already declares it. If you forked the repo, you must enable Actions in the
fork's settings.

**Q: `bun run semgrep` says "semgrep: command not found".**
A: Install Semgrep: `pip install semgrep` or `brew install semgrep`. The CI
workflow installs it automatically.

**Q: The audit report has ERROR findings but the build is green. Why?**
A: The local `audit.sh` script is informational — it does not fail the build.
The CI workflows that *do* fail the build are `ci.yml` (lint, typecheck,
build) and `codeql.yml` (CodeQL on `error` severity).

**Q: Can I run the audit without Bun (e.g. with plain Node)?**
A: Yes, but you lose lockfile-based checks. `npm install && npm run audit`
works for everything except `bun audit` (replace with `npm audit`).

**Q: Where is the SBOM?**
A: Run `bun run sbom` to generate `audit-reports/sbom.cdx.json`. The
supply-chain CI workflow also uploads it as an artifact.
