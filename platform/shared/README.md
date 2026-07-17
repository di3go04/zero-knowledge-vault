# ZK Vault — Shared Platform Code

This directory contains code shared across all platform implementations.

## Structure

```
platform/shared/
├── api-client.ts        # HTTP client for the vault API (fetch wrapper)
├── crypto-client.ts     # Browser crypto primitives (Web Crypto API wrapper)
├── totp.ts              # TOTP generation (RFC 6238) for authenticator features
└── types.ts             # Shared TypeScript types
```

## Usage

Each platform imports these modules directly or via a build step:

- **Chrome/Edge/Firefox/Safari:** Copied or symlinked into the extension bundle
- **React Native:** Copied to `platform/mobile/src/services/` with RN adapters
- **Tauri:** Available to the web frontend via the `src/` directory
- **Smartwatch:** TOTP logic extracted independently

The source of truth lives in `src/lib/` within the main web app. These shared
files are platform-specific wrappers that reference the same cryptographic primitives.
