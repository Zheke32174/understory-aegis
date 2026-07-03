package com.understory.aegis

import android.content.Context
import com.understory.security.VaultResetHooks

/**
 * aegis's thin glue for the shared [com.understory.security.VaultRecoveryScreen]
 * reset flow (design §4.2). All app-specific vault knowledge lives behind these
 * four calls so the shared screen stays app-agnostic.
 *
 * @param onSetup routes the UI back to the Setup stage after a wipe (the reset
 *                screen calls [goToSetup] from its DONE step).
 */
class AegisResetHooks(private val onSetup: () -> Unit) : VaultResetHooks {

    override fun exists(ctx: Context): Boolean = AegisVault.exists(ctx)

    /**
     * Build the cleartext export payload from an unlocked vault handle for the
     * export-first step. Null when the vault can't be read (key invalidated) —
     * the shared ResetPlan then skips the export step, which is correct.
     */
    override fun exportPayload(unlocked: Any): ByteArray? =
        (unlocked as? UnlockedAegisVault)?.let {
            AegisVault.serialize(it.contents).toByteArray(Charsets.UTF_8)
        }

    /** Delete the vault file AND the device-auth Keystore key. */
    override fun wipe(ctx: Context) {
        AegisVault.delete(ctx)
        AegisVaultManager.clear()
    }

    override fun goToSetup() = onSetup()
}
