# understory-aegis — Understory OTP

Rootless TOTP/HOTP authenticator (store name **Understory OTP**; package id remains `com.understory.aegis`). The project is alpha and is still working through the suite release blockers.

## Security and distribution hold

**Do not treat historical CI/debug APKs as authenticated releases.** The suite's former shared debug private key became public when the Android repositories were split from a private source. Its certificate can no longer prove authorship, integrity, sibling identity, or capability authority.

Automatic GitHub Release publication of debug APKs is disabled on this draft. The repository currently provides source and read-only validation only. A future downloadable release must be built with the separately held offline release key, carry checksums and provenance, and pass the coordinated suite migration checks.

Previously installed APKs signed with the revoked debug identity will not update in place to a release-signed APK. Android requires uninstalling the old debug build before installing a differently signed release candidate.

## Local development build

Requires JDK 17+ and Android SDK platform 35 with build-tools 35.0.0.

```bash
gradle :aegis:assembleDebug
gradle test
```

Local debug builds are development fixtures only. They are not supported distribution artifacts and must not be represented as suite-authenticated releases.

## Provenance and suite relationship

Split 2026-07-02 from private `Zheke32174/underward` `android/` at commit `f867493` into per-app repositories.

Part of the Understory Suite: rootless, local-first Android security applications using public Android APIs and no network access unless explicitly enabled by the user.

Shared modules are vendored for self-contained builds. Their canonical editing home is [`understory-common`](https://github.com/Zheke32174/understory-common). The signing-identity containment and migration source is draft PR #5 there; downstream trust-root removal must remain synchronized with that canonical change.

## Release verification target

A future release candidate must prove all of the following before publication:

- signed by the offline release certificate declared by the canonical suite source;
- self-signature enforcement succeeds;
- sibling attestation rejects debug/re-signed peers;
- untrusted peers contribute no capabilities;
- checksums and source commit are verified by the consumer;
- install, update, rollback, export, and removal behavior are documented and tested.
