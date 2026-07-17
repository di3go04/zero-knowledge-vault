# ZK Vault — Chrome Extension (Manifest V3)

Browser extension for the Zero-Knowledge Vault password manager.

## Structure

```
platform/chrome-extension/
├── manifest.json        # Manifest V3
├── service-worker.js    # Background service worker (session mgmt, messaging)
├── content-script.js    # Page injection for autofill
├── popup/
│   ├── index.html       # Popup entry
│   ├── popup.js         # Popup logic (auth, secret list, autofill)
│   └── popup.css        # Popup styles
└── icons/               # Extension icons (16, 48, 128px)
```

## Development

1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" and select this directory

## Shared Dependencies

See `platform/shared/` for:
- `api-client.ts` — HTTP client (auth, secret CRUD)
- `crypto-client.ts` — Browser crypto primitives (Web Crypto API)

## Build

```bash
# Bundle for production (uses esbuild or similar)
npm run build:chrome
```
