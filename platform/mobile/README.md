# ZK Vault — React Native Mobile App

## Structure

```
platform/mobile/
├── App.tsx                    # Application entry point
├── package.json               # Dependencies
├── tsconfig.json              # TypeScript configuration
├── src/
│   ├── navigation/
│   │   └── RootNavigator.tsx  # Stack navigator (Login/Vault/Detail/Settings)
│   ├── screens/
│   │   ├── LoginScreen.tsx    # Email + master password auth
│   │   ├── VaultScreen.tsx    # Secret list
│   │   ├── SecretDetailScreen.tsx  # Encrypted blob viewer
│   │   └── SettingsScreen.tsx # Logout, app preferences
│   └── services/
│       ├── AuthContext.tsx     # Session state management
│       └── api-client.ts      # HTTP client for vault API
└── ios/                       # Xcode project (generated)
└── android/                   # Gradle project (generated)
```

## Key Decisions

- **No Web Crypto API in React Native** — Crypto operations delegated to
  native Keychain/Keystore via `react-native-keychain`. Symmetric encryption
  uses TweetNaCl (portable, auditable NaCl implementation).
- **Session token** stored in AsyncStorage; biometric unlock via Keychain.
- **Navigation** via React Navigation 7 with native stack.

## Setup

```bash
cd platform/mobile
bun install
npx react-native run-ios      # iOS simulator
npx react-native run-android   # Android emulator
```
