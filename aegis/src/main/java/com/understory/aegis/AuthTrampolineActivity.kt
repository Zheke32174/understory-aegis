package com.understory.aegis

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.understory.security.Diagnostics
import com.understory.security.Tamper
import javax.crypto.Cipher

/**
 * Transparent, short-lived activity the IME launches to obtain a *scoped*,
 * time-boxed unlock (design §2.2). It never touches MainActivity's lifecycle
 * locks: on biometric success it mints a SEPARATE [UnlockedAegisVault] and hands
 * it to [AegisVaultManager.setImeSession] with a TTL, then finishes. Focus
 * returns to the user's target app; the IME re-queries [AegisVaultManager.imeSession]
 * and renders the live list until the TTL expires.
 *
 * Draws nothing (transparent theme). The only visible surface is the
 * BiometricPrompt sheet, whose subtitle states the TTL honestly.
 */
class AuthTrampolineActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Diagnostics.log("aegis.Trampoline", "onCreate")

        // Same hard-refuse posture as the rest of the app.
        val debuggerAttached = android.os.Debug.isDebuggerConnected() ||
            android.os.Debug.waitingForDebugger()
        if (debuggerAttached || Tamper.check(applicationContext).hardFail) {
            finish()
            return
        }

        // Keep this surface out of screenshots/recents like every vault surface.
        runCatching {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }

        if (!AegisVault.exists(this)) {
            // Nothing to unlock — the user must set up the vault in the app.
            finish()
            return
        }

        promptUnlock()
    }

    private fun promptUnlock() {
        val cipher: Cipher = try {
            val iv = AegisVault.ivForUnlock(this)
            com.understory.security.Crypto.deviceAuthCipherForDecrypt(iv)
        } catch (t: Throwable) {
            Diagnostics.error("aegis.Trampoline", "cipher init failed: ${t.message}")
            finish()
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher
                if (c == null) { finish(); return }
                runCatching {
                    val v = AegisVault.unlockV2(this@AuthTrampolineActivity, c)
                    // Scoped IME grant — NOT setUnlocked (that is MainActivity's
                    // app-session channel). MainActivity's lock-on-leave is
                    // untouched; this session lives and dies on its own TTL.
                    AegisVaultManager.setImeSession(v, IME_SESSION_TTL_MS)
                }.onFailure {
                    Diagnostics.error("aegis.Trampoline", "unlock failed: ${it.message}")
                }
                finish()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Diagnostics.log("aegis.Trampoline", "auth error $errorCode")
                finish()
            }
        }

        val prompt = BiometricPrompt(this, executor, callback)
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock the aegis keyboard")
            .setSubtitle("Unlocks the aegis keyboard for ${IME_SESSION_TTL_MS / 1000} seconds")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()
        runCatching { prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher)) }
            .onFailure {
                Diagnostics.error("aegis.Trampoline", "prompt.authenticate threw: ${it.message}")
                finish()
            }
    }

    companion object {
        /** IME session lifetime — honest 90s, surfaced in the prompt + IME header. */
        const val IME_SESSION_TTL_MS: Long = 90_000L
    }
}
