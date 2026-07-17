# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

We take the security of Zero-Knowledge Vault seriously. If you believe you
have found a security vulnerability, please report it to us as described below.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **security@zkvault.dev** (if public)
or open a [GitHub Security Advisory](https://github.com/di3go04/zero-knowledge-vault/security/advisories/new).

You should receive a response within 48 hours. If for some reason you do not,
please follow up via email to ensure we received your original message.

### What to include

- Type of issue (e.g. buffer overflow, timing attack, cryptographic weakness)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### What to expect

- We will acknowledge receipt of your report within 48 hours
- We will provide an estimated timeline for a fix
- We will notify you when the issue is resolved
- We will credit you in the release notes (unless you prefer to remain anonymous)

## Disclosure Policy

When we receive a security report, we will:

1. Confirm receipt and begin investigation
2. Determine the severity and impact
3. Work on a fix
4. Release a security advisory on GitHub once the fix is deployed

## Comments on This Policy

If you have suggestions on how this process could be improved, please submit
a pull request or open an issue for discussion.

## Threat Model

For a detailed threat model and security architecture, see:
- [Security Audit Report](docs/SECURITY_AUDIT_REPORT.md)
- [Architecture Documentation](README.md#arquitectura-técnica)

## Cryptographic Claims

This project provides **zero-knowledge guarantees**:

- The server **never** receives master passwords, private keys, AES keys,
  or secret contents in plaintext
- All encryption/decryption happens client-side using Web Crypto API
- The server only stores encrypted blobs and public key material
- See [README](README.md#garantías-zero-knowledge) for the full guarantees
