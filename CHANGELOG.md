# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Enterprise features (#21-#40): SCIM, SAML/OIDC, LDAP, RBAC, Groups, Approvals,
  Break-glass, Webhooks, Admin Dashboard, Compliance, eDiscovery, DLP,
  Retention Policies, Directory Sync, SLA Monitors, Multitenant, Branding,
  Admin API, Self-service Portal
- Collaboration features (#41-#52): One-time shares, temp vaults, secret versions,
  comments, notifications, activity feed, share approval, tags, import/export,
  email sharing, access requests, share audit
- Security features (#17-#20): Adaptive rate limiting, CAPTCHA, side-channel
  protection, audit log
- Security features (#11-#16): Breach detection, password health, SSH keys,
  metadata encryption
- Security features (#8-#10): Memory zeroing, compromise detection, password policies
- i18n support: 15 languages (AR, DE, EN, ES, FR, HI, IT, JA, KO, NL, PL, PT, RU, TR, ZH)
- Multi-platform extensions: Chrome, Firefox, Edge, Safari, Desktop (Tauri),
  Mobile (React Native), Smartwatch (WearOS, watchOS)
- CLI tool for admin operations
- WebAuthn/Passkeys/FIDO2 support

### Security
- Zero-knowledge architecture: all encryption happens client-side
- AES-256-GCM for all secret data
- Argon2id (64 MiB, memory-hard KDF) with PBKDF2 fallback
- RSA-OAEP 2048-bit for key wrapping
- ECDH P-256 + ECDSA for multi-device enrollment
- BIP-39 recovery (24 words, 256 bits)
- HMAC-signed tokens with server-side revocation
- Anti-enumeration decoy login
- Memory zeroing on all crypto operations

## [0.2.0] - 2025-01-15

### Added
- Multi-device enrollment flow with ECDH + ECDSA challenge-response
- Rate limiting on sensitive endpoints
- Zod validation schemas for all API endpoints
- Playwright E2E tests

### Changed
- Migrated to Next.js 16 App Router with Turbopack
- Upgraded to Tailwind CSS v4
- Updated shadcn/ui to New York style

## [0.1.0] - 2024-10-01

### Added
- Initial release with core zero-knowledge vault functionality
- User registration with RSA-PSS proof-of-possession
- Client-side encryption with Web Crypto API
- Secret CRUD operations
- Basic sharing between users
- Prisma ORM with SQLite
