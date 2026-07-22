package com.understory.aegis

import com.understory.security.OtpAuthEntry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * RFC 6238 Appendix B known-answer tests for [AegisCode.totp] across every
 * algorithm and the 8-digit case — the axes the vendored [com.understory.security.Totp]
 * hardcodes and therefore gets wrong for non-default entries (audit A-U1).
 *
 * RFC 6238 uses different-length ASCII seeds per algorithm:
 *   SHA1   → "12345678901234567890"                 (20 bytes)
 *   SHA256 → "12345678901234567890123456789012"     (32 bytes)
 *   SHA512 → "1234567890...1234"                     (64 bytes)
 * All vectors are 8-digit, period 30. Robolectric supplies the JCA Mac
 * providers on the host JVM (Base32 encode/decode is exercised too).
 */
@RunWith(RobolectricTestRunner::class)
class AegisCodeTest {

    private fun asciiSeed(len: Int): ByteArray {
        val pattern = "1234567890"
        val sb = StringBuilder()
        while (sb.length < len) sb.append(pattern)
        return sb.substring(0, len).toByteArray(Charsets.US_ASCII)
    }

    private fun entry(
        seed: ByteArray,
        algo: OtpAuthEntry.Algorithm,
        digits: Int = 8,
        period: Int = 30,
    ): AegisEntry = AegisEntry(
        issuer = "rfc",
        account = "b",
        secretB64 = android.util.Base64.encodeToString(seed, android.util.Base64.NO_WRAP),
        type = OtpAuthEntry.Type.TOTP,
        digits = digits,
        period = period,
        algorithm = algo,
    )

    // --- SHA1 8-digit vectors (RFC 6238 Appendix B) ---

    @Test fun sha1_t59() =
        assertEquals("94287082", AegisCode.totp(entry(asciiSeed(20), OtpAuthEntry.Algorithm.SHA1), 59L))

    @Test fun sha1_t1111111109() =
        assertEquals("07081804", AegisCode.totp(entry(asciiSeed(20), OtpAuthEntry.Algorithm.SHA1), 1111111109L))

    @Test fun sha1_t20000000000() =
        assertEquals("65353130", AegisCode.totp(entry(asciiSeed(20), OtpAuthEntry.Algorithm.SHA1), 20000000000L))

    // --- SHA256 8-digit vectors ---

    @Test fun sha256_t59() =
        assertEquals("46119246", AegisCode.totp(entry(asciiSeed(32), OtpAuthEntry.Algorithm.SHA256), 59L))

    @Test fun sha256_t1111111109() =
        assertEquals("68084774", AegisCode.totp(entry(asciiSeed(32), OtpAuthEntry.Algorithm.SHA256), 1111111109L))

    @Test fun sha256_t20000000000() =
        assertEquals("77737706", AegisCode.totp(entry(asciiSeed(32), OtpAuthEntry.Algorithm.SHA256), 20000000000L))

    // --- SHA512 8-digit vectors ---

    @Test fun sha512_t59() =
        assertEquals("90693936", AegisCode.totp(entry(asciiSeed(64), OtpAuthEntry.Algorithm.SHA512), 59L))

    @Test fun sha512_t1111111109() =
        assertEquals("25091201", AegisCode.totp(entry(asciiSeed(64), OtpAuthEntry.Algorithm.SHA512), 1111111109L))

    @Test fun sha512_t20000000000() =
        assertEquals("47863826", AegisCode.totp(entry(asciiSeed(64), OtpAuthEntry.Algorithm.SHA512), 20000000000L))

    // --- 6-digit SHA1 agrees with the last-6 of the RFC 8-digit vector ---

    @Test fun sha1_6digit_lastSixOfVector() {
        // 94287082 → last-6 = 287082.
        assertEquals("287082", AegisCode.totp(entry(asciiSeed(20), OtpAuthEntry.Algorithm.SHA1, digits = 6), 59L))
    }

    // --- period != 30 changes the counter, hence the code ---

    @Test fun period60_usesHalfTheCounter() {
        // At t=60 with period 60, counter=1; at t=60 with period 30, counter=2.
        // They must differ (regression guard for period being honored).
        val p60 = AegisCode.totp(entry(asciiSeed(20), OtpAuthEntry.Algorithm.SHA1, period = 60), 60L)
        val p30 = AegisCode.totp(entry(asciiSeed(20), OtpAuthEntry.Algorithm.SHA1, period = 30), 60L)
        org.junit.Assert.assertNotEquals(p60, p30)
    }

    // --- grouping / bullet helpers ---

    @Test fun groupCode_shapes() {
        assertEquals("123 456", AegisCode.groupCode("123456"))
        assertEquals("123 4567", AegisCode.groupCode("1234567"))
        assertEquals("1234 5678", AegisCode.groupCode("12345678"))
    }

    @Test fun bullets_matchDigitWidths() {
        assertEquals("●●● ●●●", AegisCode.bullets(6))
        assertEquals("●●● ●●●●", AegisCode.bullets(7))
        assertEquals("●●●● ●●●●", AegisCode.bullets(8))
    }
}
