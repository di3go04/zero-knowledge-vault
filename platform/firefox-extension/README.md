# ZK Vault — Firefox Extension

## Structure

```
platform/firefox-extension/
├── manifest.json      # Manifest V2 (Firefox compatible)
├── background.js      # Non-persistent background script (browser.* API)
├── content-script.js  # Autofill injection
├── popup/             # Symlink/copy from chrome-extension/popup/
└── icons/             # Extension icons
```

## Differences from Chrome

- Uses `manifest_version: 2` (Firefox MV3 support is partial)
- Uses `browser.*` API instead of `chrome.*`
- Session storage uses `browser.storage.local` (persistent)
- Background is non-persistent Event Pages

## Development

1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `manifest.json`
