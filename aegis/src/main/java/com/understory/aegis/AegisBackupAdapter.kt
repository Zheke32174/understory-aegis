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
 * Import semantics: **merge with dedup, prefer existing** via the shared
 * [AegisMerge] (design §3.4), keyed on `(issuer, account, secretB64)` so the
 * file-import, QR-migration, and adapter paths all agree. A duplicate (same
 * issuer/account AND same secret) is skipped; a same-account entry with a
 * DIFFERENT secret (re-enrollment) is kept, matching the file-import path.
 *
 * Returned summary string is human-readable and used by the caller's
 * Toast/snackbar surface.
 */
object AegisBackupAdapter : BackupAdapter {

    override val appId: String = "com.understory.aegis"

    /**
     * schemaVersion 2 = the split-key recovery model (design §3.4 /
     * shared-vault-recovery §3.4): the encrypted `.usbe` payload is this
     * adapter's cleartext vault JSON encrypted under the user-held RECOVERY
     * key, not the hardware KEK, so it restores onto a fresh vault on a new
     * device. This meets [com.understory.backup.VaultRecoveryEnvelope.SchemaVersions.SPLIT_KEY_MIN].
     * The JSON shape itself is unchanged from v1 and readers tolerate unknown
     * fields, so [import] accepts v1 and v2 payloads identically.
     */
    override val schemaVersion: Int = 2

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

        val result = AegisMerge.mergeEntries(vault.contents.entries, incoming.entries)
        if (result.added > 0) {
            vault.contents = vault.contents.copy(entries = result.merged)
            vault.save()
        }

        return buildString {
            append("Imported ${result.added} new ")
            append(if (result.added == 1) "entry" else "entries")
            if (result.skipped > 0) {
                append("; ${result.skipped} duplicate")
                if (result.skipped != 1) append("s")
                append(" kept existing")
            }
            append(". ${vault.contents.entries.size} total.")
        }
    }
}
