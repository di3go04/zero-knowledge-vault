# ZK Vault — Tauri Desktop App

## Structure

```
platform/desktop/
├── package.json               # Node dependencies (Tauri CLI, Next.js)
├── src/                       # Frontend (Next.js app)
│   └── index.html             # Entry point (references web build)
├── src-tauri/
│   ├── Cargo.toml             # Rust dependencies
│   ├── tauri.conf.json        # Tauri configuration (window, CSP, plugins)
│   ├── build.rs               # Tauri build script
│   ├── icons/                 # App icons (png, ico, icns)
│   └── src/
│       ├── lib.rs             # Tauri app entry, command registration
│       ├── crypto.rs          # Native Argon2id + AES-256-GCM
│       ├── keychain.rs        # OS keychain integration
│       └── lock.rs            # Auto-lock timer
```

## Key Decisions

- **Tauri v2** with Rust backend for native operations
- **Clipboard plugin** for secure copy/paste with auto-clear timer
- **Store plugin** for persistent preferences (auto-lock timeout, theme)
- **Native Argon2id** via `argon2` Rust crate (faster than WASM in browser)
- **OS Keychain** via `keyring` crate for session token storage
- **Auto-lock** timer that locks the vault after inactivity

## Development

```bash
cd platform/desktop
bun install
bun tauri dev      # Hot-reload with Next.js
bun tauri build    # Production build (.dmg, .msi, .AppImage)
```

## Security Considerations

- The Rust backend NEVER receives plaintext secrets — only the encrypted blobs.
- Crypto keys live in the webview's memory (JavaScript CryptoKey objects).
- The keychain stores only the session token, not master keys.
