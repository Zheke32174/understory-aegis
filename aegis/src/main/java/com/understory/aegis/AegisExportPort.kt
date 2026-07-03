package com.understory.aegis

import com.understory.backup.VaultRecoveryEnvelope
import com.understory.security.Crypto
import com.understory.security.VaultExportPort
import java.io.InputStream
import java.io.OutputStream

/**
 * aegis's bridge for the shared [VaultExportScreen] / [VaultImportScreen]
 * (design §3, §4). Wraps [AegisBackupAdapter]'s cleartext vault JSON in the
 * suite's one encrypted at-rest format ([VaultRecoveryEnvelope] +
 * `AesGcmPassphraseCodec`) under the user-held recovery key.
 *
 * common-security can't reference common-backup (module graph runs
 * common-backup → common-security), so this bridge lives in the app module,
 * which vendors both — exactly the pattern [VaultExportPort]'s KDoc prescribes.
 */
object AegisExportPort : VaultExportPort {

    override val appId: String = AegisBackupAdapter.appId
    override val schemaVersion: Int = AegisBackupAdapter.schemaVersion
    override val appLabel: String = "OTP"

    /**
     * Build the cleartext payload from the passed unlocked vault handle. The
     * shared screen hands back exactly what the caller gave it, so we accept a
     * [UnlockedAegisVault] and serialize its live contents (excluding nothing —
     * the legacy master-KEK entry is already filtered at load).
     */
    override fun buildPayload(unlocked: Any?): ByteArray? {
        val vault = unlocked as? UnlockedAegisVault ?: AegisVaultManager.current ?: return null
        return AegisVault.serialize(vault.contents).toByteArray(Charsets.UTF_8)
    }

    override fun writeEncrypted(out: OutputStream, payload: ByteArray, key: CharArray, label: String) {
        VaultRecoveryEnvelope.writeEncrypted(
            out = out,
            appId = appId,
            schemaVersion = schemaVersion,
            plaintext = payload,
            recoveryKeyChars = key,
            label = label,
        )
    }

    override fun peekAppId(input: InputStream): String =
        VaultRecoveryEnvelope.open(input).appId

    override fun decryptAndImport(input: InputStream, key: CharArray): String {
        val opened = VaultRecoveryEnvelope.open(input)
        val payload = VaultRecoveryEnvelope.decrypt(opened, key)
        try {
            return AegisBackupAdapter.import(payload, opened.schemaVersion)
        } finally {
            Crypto.wipe(payload)
        }
    }
}
