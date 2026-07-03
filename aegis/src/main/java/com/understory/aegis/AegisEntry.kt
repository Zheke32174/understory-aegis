package com.understory.aegis

import com.understory.security.OtpAuthEntry
import com.understory.security.HotpSecret
import org.json.JSONObject
import java.util.UUID

/**
 * A single TOTP/HOTP entry stored in aegis's vault.
 *
 * The secret is held as a base64-encoded String here so it survives JSON
 * serialization. In-memory it's still recoverable as raw bytes via [secretBytes].
 * When the vault locks, the entries list is replaced (passgen pattern), so
 * the String references become GC-eligible.
 *
 * For HOTP the [counter] increments every time a code is generated and the
 * vault is re-saved.
 */
data class AegisEntry(
    val id: String = UUID.randomUUID().toString(),
    val issuer: String,
    val account: String,
    val secretB64: String,
    val type: OtpAuthEntry.Type = OtpAuthEntry.Type.TOTP,
    val digits: Int = 6,
    val period: Int = 30,
    val counter: Long = 0,
    val algorithm: OtpAuthEntry.Algorithm = OtpAuthEntry.Algorithm.SHA1,
    val createdMs: Long = System.currentTimeMillis(),
) {
    /** Materialize the secret bytes for code generation. Caller must wipe. */
    fun secretBytes(): ByteArray =
        android.util.Base64.decode(secretB64, android.util.Base64.NO_WRAP)

    /**
     * Inverse of [fromOtpAuth]: build an [OtpAuthEntry] carrying this entry's
     * raw secret + all params, for export via [OtpAuthEntry.toUri] or the
     * Aegis-compatible JSON exporter. The returned entry owns a fresh secret
     * ByteArray; caller must [OtpAuthEntry.wipeSecret] it after use.
     */
    fun toOtpAuthEntry(): OtpAuthEntry = OtpAuthEntry(
        type = type,
        issuer = issuer,
        account = account,
        secret = secretBytes(),
        digits = digits,
        period = period,
        counter = counter,
        algorithm = algorithm,
    )

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("issuer", issuer)
        put("account", account)
        put("secret_b64", secretB64)
        put("type", type.name)
        put("digits", digits)
        put("period", period)
        put("counter", counter)
        put("algorithm", algorithm.name)
        put("created_ms", createdMs)
    }

    companion object {
        fun fromJson(o: JSONObject): AegisEntry = AegisEntry(
            id = o.optString("id", UUID.randomUUID().toString()),
            issuer = o.optString("issuer", ""),
            account = o.optString("account", ""),
            secretB64 = o.optString("secret_b64", ""),
            type = runCatching {
                OtpAuthEntry.Type.valueOf(o.optString("type", "TOTP"))
            }.getOrDefault(OtpAuthEntry.Type.TOTP),
            digits = o.optInt("digits", 6),
            period = o.optInt("period", 30),
            counter = o.optLong("counter", 0),
            algorithm = runCatching {
                OtpAuthEntry.Algorithm.valueOf(o.optString("algorithm", "SHA1"))
            }.getOrDefault(OtpAuthEntry.Algorithm.SHA1),
            createdMs = o.optLong("created_ms", System.currentTimeMillis()),
        )

        /** Build from an [OtpAuthEntry] (typically the result of QR import). */
        fun fromOtpAuth(parsed: OtpAuthEntry): AegisEntry {
            val secretB64 = android.util.Base64.encodeToString(
                parsed.secret,
                android.util.Base64.NO_WRAP,
            )
            return AegisEntry(
                issuer = parsed.issuer,
                account = parsed.account,
                secretB64 = secretB64,
                type = parsed.type,
                digits = parsed.digits,
                period = parsed.period,
                counter = parsed.counter,
                algorithm = parsed.algorithm,
            )
        }
    }
}

data class AegisVaultContents(val entries: List<AegisEntry>)
