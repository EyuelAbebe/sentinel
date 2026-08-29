# Sentinel Browser Extension

Shows privacy risk scores for every site you visit, powered by the local Sentinel daemon.

## Requirements

- Sentinel running locally with the HTTP API enabled (Phase 9): `sentinel serve`
- Chrome 116+, Edge 116+, Brave, or Firefox 109+

## Load in Chrome (development)

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select this `browser-extension/` directory
5. The Sentinel icon appears in your toolbar

## Load in Firefox (development)

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `browser-extension/manifest-firefox.json`

## How it works

```
Browser page load
      ↓
background.js (service worker)
      ↓ fetch hostname
Sentinel HTTP API  (:7173/classify?domain=...)
      ↓ returns {organization, category, confidence}
popup.js
      ↓ renders risk badge + recent sites
```

## Privacy badge colours

| Badge | Category | Meaning |
|---|---|---|
| 🟢 FIRST PARTY | first_party | Site's own infrastructure |
| 🔵 CDN | cdn | Content delivery network |
| 🔵 CLOUD API | cloud_api | Cloud platform |
| 🟡 ANALYTICS | analytics | Behavioural analytics |
| 🟠 TELEMETRY | telemetry | App/OS error reporting |
| 🔴 TRACKING | tracking | Cross-site user tracking |
| 🔴 ADVERTISING | advertising | Targeted advertising |
| ⚪ UNKNOWN | unknown | Not in sentinel database |

## Building for production

The extension uses plain JavaScript with no build step required.  To package:

```bash
cd browser-extension
zip -r sentinel-extension.zip . -x "*.git*" -x "README.md"
```
