# Release-readiness checkpoint

## Identity

- Repository: `Zheke32174/understory-aegis`
- Checkpoint branch: `security/public-signing-containment-v1`
- Reviewed default head: `9d25e96fbc06db8466ff876a365c1ce2426975a8`
- Validated complete branch head: `e2868350497043e5712a10884f0b9caea04dc0b8`
- Coordination: `Zheke32174/understory-common#3`

## Last completed scope

Public signing identity, APK publication authority, current-tree key exposure,
install-verification claims, vendored trust primitives, debug assembly, complete
unit tests, security reporting, and licensing presence.

## Resolved on this draft

- Removed the shared public debug private key from the current tree.
- Removed committed debug-signing configuration.
- Revoked debug signatures for authorship, sibling identity, and capabilities.
- Replaced automatic latest-release publication with read-only validation.
- Removed tag force-update and release-asset overwrite authority.
- Corrected install-verification and public-distribution claims.
- Added security guidance, incident provenance, key ignore rules, and a
  deterministic signing-boundary validator that also rejects stale README trust
  claims.
- Corrected the RFC 6238 SHA-256 test vector to use the timestamp associated with
  its expected value rather than weakening the implementation or skipping it.

## Validation receipts

GitHub Actions run `29920347556` passed at exact complete branch head
`e2868350497043e5712a10884f0b9caea04dc0b8`:

- immutable read-only checkout;
- public signing and presentation boundary validation;
- Android SDK provisioning;
- debug APK assembly without a committed suite signing key;
- all unit tests, including the corrected RFC 6238 vectors;
- durable unit-test receipt upload.

## Changed conclusion

The current source, presentation, build, and test boundary is green. The
repository is not publishable because historical artifacts, release governance,
licensing, and an authorized signed candidate remain unresolved.

## Open blockers

- The key remains reachable in public history and prior artifacts/releases.
- Existing movable tags and release assets need an explicit steward disposition.
- No independently verified signed release candidate exists.
- No immutable versioned publication workflow is approved.
- The repository has no explicit license; no license was invented.
- Offline release-key custody remains unverified.
- Branch rules, secret scanning, push protection, private vulnerability
  reporting, and immutable-release settings need administrative verification.
- All sibling repositories must complete the same exact-head boundary before the
  suite can claim coordinated release identity.

## Reconsideration triggers

New commit, changed CI, newly discovered key material, changed release asset,
license decision, signing rotation, changed public claim, changed repository
visibility, or explicit steward request.

## Next action

Review the remaining sibling receipts, select a source license, and decide the
disposition of prior public debug releases before designing any authenticated
release candidate.
