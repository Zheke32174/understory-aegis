# Release-readiness checkpoint

- Repository: `Zheke32174/understory-aegis`
- Reviewed head: `9d25e96fbc06db8466ff876a365c1ce2426975a8`
- Draft: `security/contain-debug-release-v1`
- Status: **HOLD — debug distribution contained; coordinated signing migration pending**

## Completed scope

Reviewed signing claims, debug APK publication, workflow authority, mutable tags/assets, consumer verification, install/update consequences, and suite trust dependencies.

## Resolved on this draft

- Replaced automatic write-enabled release-on-push behavior with read-only build and test validation.
- Removed APK artifact upload and normal/latest GitHub Release publication.
- Removed force-moved release tags and overwriteable asset behavior from the workflow.
- Pinned retained Actions to full commit SHAs, disabled checkout credential persistence, set explicit read-only permissions, and fixed the runner image to Ubuntu 24.04.
- Corrected the README so debug builds are no longer represented as authenticated downloads.

## Open blockers

1. Integrate the canonical signing-identity containment from `understory-common`.
2. Remove the vendored shared debug key in the same coordinated change that updates runtime trust behavior.
3. Confirm the offline release private key remains outside GitHub and CI.
4. Decide, with explicit authorization, how to handle existing public debug releases and mutable tags.
5. Produce release-signed self-check, sibling-attestation, capability-denial, install, update, export, rollback, and removal receipts.
6. Add checksums and consumer-verifiable provenance to any future release candidate.
7. Verify branch rules, Action-pin enforcement, secret scanning, push protection, private vulnerability reporting, and release immutability administratively.

## Reconsideration triggers

Reprocess on a workflow or branch change, signing-key status change, canonical trust-root update, existing release cleanup, a release-signed fixture, changed public download claim, or explicit steward request.

## Next action

Propagate publication containment to the remaining affected app repositories, then apply the canonical trust-root migration as one coordinated suite update.

No default branch, release, tag, repository setting, installed app, or live system was changed.
