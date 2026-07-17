# ZK Vault — Edge Extension

## Structure

```
platform/edge-extension/
├── manifest.json        # Manifest V3 (Edge compatible)
├── service-worker.js    # Service worker (chrome.* API)
├── content-script.js    # Autofill injection
├── popup/               # Copy from chrome-extension/popup/
└── icons/               # Extension icons
```

Edge's extension API is identical to Chrome's Manifest V3. The extension
submits to the Microsoft Edge Add-ons store via Partner Center.

## Development

1. Open `edge://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" and select this directory
