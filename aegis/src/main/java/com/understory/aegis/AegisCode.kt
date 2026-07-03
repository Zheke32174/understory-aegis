package com.understory.aegis

import com.understory.security.Crypto
import com.understory.security.OtpAuthEntry
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Parameter-correct OTP generation for aegis (design §1).
 *
 * The vendored [com.understory.security.Totp] is byte-identical across the
 * suite and hardcodes HmacSHA1 / 6-digit / 30-second (it is passgen's
 * unlock-TOTP factor, always SHA1/6/30 by its own generated secret, and is
 * canonical in `understory-common` — not editable from this repo). aegis
 * imports entries with SHA256/SHA512 algorithms, 7/8 digits, and periods other
 * than 30, so it CANNOT use `Totp.currentCode` for display: that would generate
 * codes the issuer rejects while showing a plausible countdown (audit A-U1,
 * A-U2, A-M3, A-M4).
 *
 * This helper honors every axis the entry carries — algorithm, digits, period
 * (TOTP) and counter (HOTP) — using the same RFC 4226 dynamic-truncation body
 * `Totp` uses, parameterized. It owns the secret-bytes lifecycle: it decodes,
 * computes, and wipes in a `finally` so no caller has to remember to.
 */
object AegisCode {

    /** JCA HMAC algorithm string for an entry's OTP algorithm. */
    private fun OtpAuthEntry.Algorithm.jca(): String = when (this) {
        OtpAuthEntry.Algorithm.SHA1 -> "HmacSHA1"
        OtpAuthEntry.Algorithm.SHA256 -> "HmacSHA256"
        OtpAuthEntry.Algorithm.SHA512 -> "HmacSHA512"
    }

    /**
     * Compute the current TOTP code for [entry] at [nowSeconds], honoring its
     * period / digits / algorithm. Decodes and wipes the secret internally.
     */
    fun totp(entry: AegisEntry, nowSeconds: Long): String {
        val period = if (entry.period > 0) entry.period else 30
        val counter = nowSeconds / period
        val secret = entry.secretBytes()
        return try {
            hotpCode(secret, counter, entry.digits, entry.algorithm.jca())
        } finally {
            Crypto.wipe(secret)
        }
    }

    /**
     * Compute the HOTP code for [entry] at its CURRENT counter, then persist
     * `counter + 1` to [vault] BEFORE returning — RFC 4226 clients increment
     * after generating, and persisting first means a crash can never re-serve a
     * consumed counter (the one failure worse than a wrong HOTP code, design
     * §1.4). If [UnlockedAegisVault.save] throws, this propagates and no code is
     * returned, so the on-disk counter and the served code never desync.
     *
     * The advanced entry replaces the immutable [AegisEntry] inside the vault's
     * contents by [AegisEntry.id].
     */
    fun advanceHotp(vault: UnlockedAegisVault, entry: AegisEntry): String {
        val secret = entry.secretBytes()
        val code = try {
            hotpCode(secret, entry.counter, entry.digits, entry.algorithm.jca())
        } finally {
            Crypto.wipe(secret)
        }
        val advanced = entry.copy(counter = entry.counter + 1)
        vault.contents = vault.contents.copy(
            entries = vault.contents.entries.map { if (it.id == entry.id) advanced else it },
        )
        // Persist AFTER computing the code, BEFORE returning it. Propagate on
        // failure so a code whose counter wasn't saved is never handed out.
        vault.save()
        return code
    }

    /**
     * RFC 4226 HOTP with a parameterized HMAC algorithm and digit count. Same
     * dynamic-truncation body as [com.understory.security.Totp], generalized off
     * its hardcoded SHA1/6 axes.
     */
    private fun hotpCode(secret: ByteArray, counter: Long, digits: Int, jcaAlgo: String): String {
        require(digits in 6..10) { "digits out of range: $digits" }
        val counterBytes = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            counterBytes[i] = (c and 0xFF).toByte()
            c = c ushr 8
        }
        val mac = Mac.getInstance(jcaAlgo).apply {
            init(SecretKeySpec(secret, jcaAlgo))
        }
        val hash = mac.doFinal(counterBytes)
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val truncated =
            ((hash[offset].toInt() and 0x7F) shl 24) or
                ((hash[offset + 1].toInt() and 0xFF) shl 16) or
                ((hash[offset + 2].toInt() and 0xFF) shl 8) or
                (hash[offset + 3].toInt() and 0xFF)
        var mod = 1
        repeat(digits) { mod *= 10 }
        val codeInt = truncated % mod
        return codeInt.toString().padStart(digits, '0')
    }

    // --- display formatting (design §1.3) ---

    /**
     * Group a numeric code for display the way authenticators do: 3-3 for 6,
     * 3-4 for 7, 4-4 for 8, else a single run. Used by the IME's committed-code
     * visual and (via [bullets]) by the redacted display.
     */
    fun groupCode(code: String): String = when (code.length) {
        6 -> "${code.substring(0, 3)} ${code.substring(3)}"
        7 -> "${code.substring(0, 3)} ${code.substring(3)}"
        8 -> "${code.substring(0, 4)} ${code.substring(4)}"
        else -> code
    }

    /**
     * Redacted bullets sized + spaced like [groupCode] would space a real code
     * of [digits] length, so the row layout is stable and the actual digits
     * never reach the visual tree (render-nothing doctrine).
     */
    fun bullets(digits: Int): String = when (digits) {
        6 -> "●●● ●●●"
        7 -> "●●● ●●●●"
        8 -> "●●●● ●●●●"
        else -> "●".repeat(digits.coerceAtLeast(1))
    }
}
