package com.understory.aegis

import com.understory.security.HotpSecret
import com.understory.security.OtpAuthEntry
import org.json.JSONArray
import org.json.JSONObject

/**
 * Emits the plaintext Aegis Authenticator vault schema (design §3.3) so the
 * operator's real Aegis Authenticator (`com.beemdevelopment.aegis`) can import
 * an aegis export directly — the concrete "complement, don't replace"
 * deliverable. Shape:
 *
 * ```json
 * { "version": 1,
 *   "header": { "slots": null, "params": null },
 *   "db": { "version": 3,
 *           "entries": [
 *             { "type": "totp", "uuid": "...", "name": "acct", "issuer": "Iss",
 *               "note": "", "info": { "secret": "BASE32", "algo": "SHA1",
 *                                     "digits": 6, "period": 30 } },
 *             { "type": "hotp", ..., "info": { ..., "counter": 0 } }
 *           ] } }
 * ```
 *
 * `header.slots == null` marks it UNENCRYPTED, which is exactly what real Aegis
 * expects for a plaintext import. Round-trippable through
 * [FileImports.parseAegisAuthJson] (unit-tested both directions).
 */
object AegisAuthExport {

    /** Build the Aegis-compatible plaintext JSON for [entries]. */
    fun toAegisJson(entries: List<AegisEntry>): String {
        val arr = JSONArray()
        for (e in entries) {
            val info = JSONObject().apply {
                val secretBytes = e.secretBytes()
                try {
                    put("secret", HotpSecret.encodeBase32(secretBytes))
                } finally {
                    com.understory.security.Crypto.wipe(secretBytes)
                }
                put("algo", e.algorithm.name)
                put("digits", e.digits)
                when (e.type) {
                    OtpAuthEntry.Type.TOTP -> put("period", e.period)
                    OtpAuthEntry.Type.HOTP -> put("counter", e.counter)
                }
            }
            arr.put(JSONObject().apply {
                put("type", if (e.type == OtpAuthEntry.Type.HOTP) "hotp" else "totp")
                put("uuid", e.id)
                put("name", e.account)
                put("issuer", e.issuer)
                put("note", "")
                put("info", info)
            })
        }
        val db = JSONObject().apply {
            put("version", 3)
            put("entries", arr)
        }
        val header = JSONObject().apply {
            put("slots", JSONObject.NULL)
            put("params", JSONObject.NULL)
        }
        return JSONObject().apply {
            put("version", 1)
            put("header", header)
            put("db", db)
        }.toString()
    }

    /** Join one `otpauth://` URI per entry, newline-separated (Export output #1). */
    fun toOtpAuthUriList(entries: List<AegisEntry>): String =
        entries.joinToString("\n") { e ->
            val otp = e.toOtpAuthEntry()
            try {
                otp.toUri()
            } finally {
                otp.wipeSecret()
            }
        }
}
