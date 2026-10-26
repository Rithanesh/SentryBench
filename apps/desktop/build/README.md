# Build resources

Place platform icons here before packaging:

- `icon.icns` — macOS (1024x1024 source recommended)
- `icon.ico` — Windows
- `icon.png` — Linux (512x512)

`entitlements.mac.plist` is required for macOS hardened-runtime + notarization
(see `package.json`'s `build.mac` config and `.github/workflows/release.yml`).
