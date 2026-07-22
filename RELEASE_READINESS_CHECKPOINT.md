
# Release-readiness checkpoint

## Identity

- Repository: `Zheke32174/understory-aegis`
- Checkpoint branch: `security/public-signing-containment-v1`
- Reviewed default head: `9d25e96fbc06db8466ff876a365c1ce2426975a8`
- Coordination: `Zheke32174/understory-common#3`

## Last completed scope

Public signing identity, APK publication authority, current-tree key exposure,
install-verification claims, vendored trust primitives, security reporting, and
licensing presence.

## Resolved on this draft

- Removed the shared public debug private key from the current tree.
- Removed committed debug-signing configuration.
- Revoked debug signatures for authorship, sibling identity, and capabilities.
- Replaced automatic latest-release publication with read-only validation.
- Removed tag force-update and release-asset overwrite authority.
- Corrected install-verification and public-distribution claims.
- Added security guidance, incident provenance, key ignore rules, and a
  deterministic signing-boundary validator.

## Open blockers

- The key remains reachable in public history and prior artifacts/releases.
- Existing movable tags and release assets need an explicit steward disposition.
- No independently verified signed release candidate exists.
- No immutable versioned publication workflow is approved.
- The repository has no explicit license; no license was invented.
- Offline release-key custody remains unverified.
- Branch rules, secret scanning, push protection, private vulnerability
  reporting, and immutable-release settings need administrative verification.
- All sibling repositories must integrate the same boundary before the suite can
  claim coordinated release identity.

## Validation receipts

Pending exact-head GitHub Actions validation.

## Reconsideration triggers

New commit, changed CI, newly discovered key material, changed release asset,
license decision, signing rotation, changed public claim, changed repository
visibility, or explicit steward request.

## Next action

Obtain exact-head build/test/policy receipts, then review coordinated sibling
branches and the disposition of prior public debug releases.
