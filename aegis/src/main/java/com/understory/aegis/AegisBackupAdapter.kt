package com.understory.aegis

import com.understory.backup.BackupAdapter

/**
 * Aegis's [BackupAdapter] — exposes the unlocked vault's entry list as
 * an exportable payload, and accepts an importable payload for restore.
 *
 * Payload format (schemaVersion = 1): the same UTF-8 JSON that
 * [AegisVault.serialize] / [AegisVault.parse] use for the vault's
 * on-disk plaintext. We deliberately reuse that format so the adapter
 * is round-trip-equivalent with the vault file itself — no parallel
 * schema to keep in sync, no risk of export-format and storage-format
 * drifting apart over time.
 *
 * Lifecycle requirement: the vault must be UNLOCKED. Both [export] and
 * [import] read [AegisVaultManager.current], which requires that
 * MainActivity has already authenticated via BiometricPrompt. A locked
 * vault throws `IllegalStateException`; the orchestrator (the eventual
 * backups app, or the in-app export UI) must surface that to the user
 * with a "unlock first" prompt.
 *
 * Import semantics: **merge with dedup, prefer existing**. Reasoning:
 *   - The user already has working entries; an import shouldn't destroy
 *     a known-good current state in favor of a possibly-stale backup.
 *   - Duplicates are detected by (issuer, account) tuple — the natural
 *     identity of a TOTP entry. Empty-issuer-empty-account entries are
 *     considered always-distinct (each one stands on its own).
 *   - The import's secret bytes for a duplicate are NOT applied; the
 *     existing secret wins. This is conservative — re-enrolling an
 *     account from QR is the right path to update its secret.
 *
 * Returned summary string is human-readable and used by the caller's
 * Toast/snackbar surface.
 */
object AegisBackupAdapter : BackupAdapter {

    override val appId: String = "com.understory.aegis"

    /**
     * Bump only when the JSON shape inside the payload changes
     * incompatibly. Backwards-compatible additions (a new optional
     * field with a sensible default) don't require a bump — readers
     * tolerate unknown fields per existing parse() semantics.
     */
    override val schemaVersion: Int = 1

    override fun export(): ByteArray {
        val vault = AegisVaultManager.current
            ?: throw IllegalStateException(
                "aegis vault is locked; unlock the app before exporting",
            )
        return AegisVault.serialize(vault.contents).toByteArray(Charsets.UTF_8)
    }

    override fun import(payload: ByteArray, schemaVersion: Int): String {
        require(schemaVersion <= this.schemaVersion) {
            "payload schemaVersion=$schemaVersion is newer than this build supports " +
                "(${this.schemaVersion}); upgrade aegis before importing"
        }
        val vault = AegisVaultManager.current
            ?: throw IllegalStateException(
                "aegis vault is locked; unlock the app before importing",
            )

        val payloadText = payload.toString(Charsets.UTF_8)
        val incoming = AegisVault.parse(payloadText)

        // Build an index of existing identities so dedup is O(N+M).
        // (issuer, account) is the natural unique key. Both empty means
        // "anonymous" — never deduped, every one stands on its own.
        val existingKeys = vault.contents.entries
            .filter { it.issuer.isNotEmpty() || it.account.isNotEmpty() }
            .map { it.issuer to it.account }
            .toHashSet()

        val toAdd = mutableListOf<AegisEntry>()
        var skipped = 0
        for (entry in incoming.entries) {
            val key = entry.issuer to entry.account
            val isAnonymous = entry.issuer.isEmpty() && entry.account.isEmpty()
            if (!isAnonymous && key in existingKeys) {
                skipped++
            } else {
                toAdd += entry
            }
        }

        if (toAdd.isNotEmpty()) {
            vault.contents = vault.contents.copy(
                entries = vault.contents.entries + toAdd,
            )
            vault.save()
        }

        return buildString {
            append("Imported ${toAdd.size} new ")
            append(if (toAdd.size == 1) "entry" else "entries")
            if (skipped > 0) {
                append("; $skipped duplicate")
                if (skipped != 1) append("s")
                append(" kept existing")
            }
            append(". ${vault.contents.entries.size} total.")
        }
    }
}
