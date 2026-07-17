# ZK Vault — Smartwatch 2FA (WatchOS / WearOS)

## Structure

```
platform/smartwatch/
├── shared/
│   └── totp.ts               # TOTP logic (can be ported to Swift/Kotlin)
├── watchos/
│   └── TOTPView.swift         # SwiftUI view with CryptoKit HMAC
├── wearos/
│   └── TOTPActivity.kt       # WearOS activity with javax.crypto.Mac
└── README.md
```

## Purpose

A companion watch app that displays TOTP (time-based one-time password) codes
for 2FA. The watch never stores vault master keys or performs encryption.

## Architecture

- **Secrets sync**: TOTP shared secrets are synced from the phone companion app
  via CloudKit (WatchOS) or Wearable Data Layer API (WearOS).
- **TOTP generation**: Each platform uses native crypto (CryptoKit / javax.crypto.Mac).
  The shared TypeScript file documents the algorithm for reference.
- **Security**: Secrets are stored in the watch's encrypted Keychain/Keystore.
  The watch face shows codes with a countdown progress indicator.

## Development

### WatchOS (Xcode)
Open `platform/smartwatch/watchos/` in Xcode with the watchOS target.

### WearOS (Android Studio)
Open `platform/smartwatch/wearos/` in Android Studio with the Wear OS target.
