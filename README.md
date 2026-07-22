# understory-aegis — Understory OTP

> [!CAUTION]
> **PUBLIC DEBUG SIGNING INCIDENT:** the former shared debug private key is
> public. Existing debug APKs and continuous debug releases cannot prove
> authorship and are untrusted development artifacts. Only a future APK signed
> by the externally held release key can be an authenticated Understory
> distribution. Tracking: `Zheke32174/understory-common#3`.

Rootless TOTP/HOTP authenticator (store name **Understory OTP**; package id stays `com.understory.aegis`). Parameter-correct codes (SHA1/256/512, 6/7/8-digit, any period; real HOTP counter advance), BiometricPrompt-gated vault, QR + otpauth:// + real Aegis Authenticator / Proton / Google-migration import, reachable export (encrypted `.usbe`, otpauth:// list, Aegis-compatible JSON), invalidated-key recovery + reset, and a scoped-unlock IME for typing codes without the clipboard. Complements — does not replace — Aegis Authenticator.

Status: **alpha** (functional; working the release-blockers list in understory-common).

## Build

Requires JDK 17+ and the Android SDK with platform 35 + build-tools 35.0.0.

```bash
# Copy local.properties.example to local.properties, set sdk.dir
gradle :aegis:assembleDebug
# APK: aegis/build/outputs/apk/debug/aegis-debug.apk
```

CI assembles a local debug APK and runs the unit-test suite as validation. It does not upload or publish APKs. Local debug signing is developer-specific and asserts no Understory distribution identity.

## Provenance & suite

Split 2026-07-02 from `Zheke32174/underward` `android/` (commit `f867493`) into per-app repos — one repo per suite app.

Part of the **Understory Suite** — rootless, in-bounds, local-first Android security apps (design constraints: no root, no Shizuku, public APIs only, zero network unless explicitly opted in).

Shared modules vendored here for a self-contained build: `common-security/` (+ `common-backup/`, `overlay-*/` where used). The `keystore/` directory contains documentation only; signing private keys are forbidden. **Do not edit shared modules in this repo.** Their canonical home is [`understory-common`](https://github.com/Zheke32174/understory-common); propagate changes with its `tools/sync-common.sh`.

Suite-level docs (SUITE_DESIGN, SUITE_ROADMAP, RELEASE_BLOCKERS, SAMSUNG_QUIRKS, BlackArch defense matrix + runbooks) live in `understory-common`.

## Verify your install

Debug APKs cannot be authenticated as Understory distributions. Their signer is developer-local, and the former shared debug signer is revoked.

For a future authenticated release, verify the APK certificate with `apksigner` and require the release fingerprint recorded in `common-security/.../SuitePins.kt`:

```bash
apksigner verify --print-certs the-downloaded.apk | grep -i 'SHA-256'
```

Expected authenticated release certificate:

`59a3dee7feb8262170e4dcabb3dbe7bc323abe8715ab49f5bed5133046a45c4a`

Certificate verification must be combined with an immutable versioned release, checksum/provenance verification, and the source commit. No such release receipt is claimed by this draft.
