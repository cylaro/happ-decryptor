# Happ Link Decryptor

[Live preview](https://cylaro.github.io/happ-decryptor/) · [Report an issue](https://github.com/cylaro/happ-decryptor/issues)

A browser-based workbench for `happ://` deep links: decrypt encrypted subscription links, edit the destination URL, re-encrypt through the official Happ API, and convert between client import formats. All cryptographic operations run locally in the browser.

Supported link formats: `crypt`, `crypt2`, `crypt3`, `crypt4`, `crypt5` (legacy and salted layouts).

## Features

- **Decryption** — generations 1–4 are RSA-PKCS1v15 wrappers decrypted with [node-forge](https://github.com/digitalbazaar/forge); `crypt5` uses RSA-4096 key recovery plus ChaCha20-Poly1305 via [noble-ciphers](https://github.com/paulmillr/noble-ciphers). A native-library CPU emulator ([unicorn.js](https://github.com/AlexAltea/unicorn.js)) remains as an automatic fallback. 36 bundled `crypt5` keys.
- **Link editor** — edit the destination URL and its query parameters (repeated parameters preserved), bind a HWID into the link, and generate every supported output format: plain URL, Base64 text, JSON, `v2raytun://import`, `clash://install-config`, `sing-box://import`, plus QR codes.
- **Device identity** — send subscription requests with the Happ HWID header set (`x-hwid`, `x-device-os`, `x-ver-os`, `x-device-model`, `User-Agent`) and inspect the panel response, including `x-hwid-max-devices-reached` and related headers. Requests go through a local bridge (Vite middleware) or a public proxy route.
- **[hwid-relay](https://github.com/cylaro/hwid-relay)** — companion project: a self-hosted Cloudflare Worker that lets unlimited devices share one HWID identity on panels with device limits.
- **Official encryption** — wrap any URL into a `happ://crypt5` link via the official [crypto.happ.su](https://crypto.happ.su) API, gated behind explicit consent.
- **English / Russian interface**, persisted across visits.

## Development

```bash
npm install
npm run dev        # local server with the request bridge
npm test           # unit tests (node --test)
npm run test:browser  # browser tests (Playwright, headless)
npm run build      # production build to dist/
npm run preview    # serve the production build with the bridge
```

The request bridge is a Vite middleware (`server/bridge.js`) mounted in both `configureServer` and `configurePreviewServer`. It forwards device headers to the target server and enforces loopback-only access, DNS pinning, redirect rejection, and request/response size and time limits.

## Testing

- 59 unit tests covering the crypt5/legacy encryption round trips, link parsing and editing, converters, and the HWID header contract.
- 10 Playwright browser tests covering the editor workflow, error handling, language switching, identity persistence, and mobile layout.

## Credits

Based on [LeeeeT/happ-decryptor](https://github.com/LeeeeT/happ-decryptor). The original repository is published without a license; this project keeps a visible attribution accordingly.
