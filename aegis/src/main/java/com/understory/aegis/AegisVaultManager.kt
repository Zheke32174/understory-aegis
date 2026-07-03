package com.understory.aegis

/**
 * Process-singleton that holds the currently-unlocked aegis vault, if any.
 *
 * Why this exists: the IME service ([AegisInputMethodService]) needs to
 * read vault entries to display saved-OTP suggestions, but it can't host a
 * BiometricPrompt directly (BiometricPrompt requires a FragmentActivity).
 * The IME and MainActivity share a process, so MainActivity's unlocked
 * state can be made visible to the IME via a process-scoped singleton.
 *
 * Lifecycle:
 *   - MainActivity unlocks vault (BiometricPrompt → cipher → unlock) →
 *     calls [setUnlocked] with the resulting [UnlockedAegisVault].
 *   - IME service queries [current] when the user opens the keyboard;
 *     if non-null, renders the entry list. If null, surfaces a "Open
 *     aegis to unlock first" message with a tap-to-open button.
 *   - MainActivity locks vault on background → calls [clear].
 *   - The process can also die between MainActivity's foreground and
 *     the user's IME usage; in that case [current] returns null and
 *     the IME shows the locked-state message.
 *
 * Threading: the singleton's getter/setter use atomic reference writes.
 * Not full memory hygiene (in-flight references can outlive the lock
 * call) but bounded by process death; matches the rest of the suite.
 */
object AegisVaultManager {
    // The held UnlockedAegisVault contains a Context field, which lint
    // structurally flags as StaticFieldLeak (singleton -> Context = leaked
    // Activity). The constructor coerces that Context to applicationContext
    // (see AegisVault.kt's UnlockedAegisVault declaration), so the actual
    // leak risk is mitigated. Lint's analyzer doesn't trace that coercion;
    // suppressing here. If a future change drops the .applicationContext
    // coercion, this suppression also has to come off.
    @android.annotation.SuppressLint("StaticFieldLeak")
    @Volatile private var unlocked: UnlockedAegisVault? = null

    val current: UnlockedAegisVault?
        get() = unlocked

    val isUnlocked: Boolean
        get() = unlocked != null

    fun setUnlocked(vault: UnlockedAegisVault) {
        unlocked = vault
    }

    fun clear() {
        runCatching { unlocked?.lock() }
        unlocked = null
    }

    @Volatile private var transientFlightCount = 0
    private val flightLock = Any()

    /**
     * Mark a deliberate transient occlusion (gallery SAF picker,
     * biometric prompt). While this count is > 0, the activity's onStop
     * preserves the unlocked vault rather than wiping it. Without this,
     * Samsung One UI nulls the vault during the picker round-trip and
     * the user is bounced back to the Unlock screen with no result.
     */
    fun beginTransientFlight() {
        synchronized(flightLock) { transientFlightCount++ }
    }

    fun endTransientFlight() {
        synchronized(flightLock) { if (transientFlightCount > 0) transientFlightCount-- }
    }

    val isInTransientFlight: Boolean
        get() = synchronized(flightLock) { transientFlightCount > 0 }
}
