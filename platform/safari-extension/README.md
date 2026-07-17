# ZK Vault — Safari Extension

## Structure

```
platform/safari-extension/
├── Info.plist                      # Safari App Extension configuration
├── safari-web-extension/
│   ├── manifest.json               # Web extension manifest (MV2)
│   ├── background.js               # Background script (browser.* API)
│   ├── content-script.js            # Autofill injection
│   └── popup/                      # Copy from chrome-extension/popup/
└── ios-app/                        # iOS wrapper app (Xcode project)
```

## Safari Extension Architecture

Safari extensions wrap a standard Web Extension inside a native iOS/macOS app:

1. **`Info.plist`** — Registers the Safari App Extension with the system
2. **`safari-web-extension/`** — Standard Web Extension (similar to Firefox MV2)
3. **`ios-app/`** — Xcode project that bundles and distributes the extension

## Development

1. Open the Xcode project in `ios-app/`
2. Select the Safari Extension target
3. Build and run on Safari (Develop → Web Extensions → Show Extension Builder)

## Converting from Chrome

Use Apple's `safari-web-extension-converter-tool` to convert Chrome extensions:

```bash
xcrun safari-web-extension-converter platform/chrome-extension/ \
  --app-name "ZK Vault" \
  --bundle-identifier "com.zk-vault.safari-extension"
```

This generates the Xcode project and `Info.plist` automatically.
