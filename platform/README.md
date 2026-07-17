# ZK Vault — Multi-Platform Implementations

This directory contains platform-specific implementations of the Zero-Knowledge Vault.

| #  | Platform          | Directory               | Status |
|----|-------------------|-------------------------|--------|
| 53 | Chrome Extension  | `chrome-extension/`     | MV3    |
| 54 | Firefox Extension | `firefox-extension/`    | MV2    |
| 55 | Edge Extension    | `edge-extension/`       | MV3    |
| 56 | Safari Extension  | `safari-extension/`     | MV2    |
| 57 | React Native App  | `mobile/`               | RN 0.78|
| 58 | Tauri Desktop App | `desktop/`              | Tauri 2|
| 59 | Smartwatch 2FA    | `smartwatch/`           | WatchOS+WearOS |

## Shared Code

`shared/` contains API clients, crypto helpers, and common types referenced by
all platforms. The source of truth for core crypto is `src/lib/crypto-client.ts`
in the main web app.

## Architecture Principles

- **Zero-knowledge**: The server never receives master passwords, private keys,
  or plaintext secrets on any platform.
- **Platform-native crypto**: Each platform uses its native crypto API
  (Web Crypto, CryptoKit, javax.crypto, rust crypto crates).
- **Session-based auth**: All platforms authenticate via the same JWT-based
  session token from the vault API.
