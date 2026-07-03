package com.understory.aegis

import com.understory.security.HotpSecret
import com.understory.security.OtpAuthEntry
import org.json.JSONArray
import org.json.JSONObject
import java.io.Reader

/**
 * File-based TOTP/HOTP importers for aegis.
 *
 * Three formats are supported:
 *
 *   1. **otpauth-migration:// URIs in a plain text file** — one URI per line.
 *      Each URI is the same payload Google Authenticator embeds in transfer
 *      QR codes; users typically obtain these by decoding the QR offline with
 *      a separate tool. This delegates to [GoogleAuthMigration.parse] per
 *      line so the existing protobuf parser is reused.
 *
 *   2. **Proton Authenticator JSON export** — actual format observed from
 *      Proton's app (validated against a real backup):
 *        { "version": 1,
 *          "entries": [
 *            { "id": "<uuid>",
 *              "content": {
 *                "uri": "otpauth://totp/...?secret=...&issuer=...&...",
 *                "entry_type": "Totp",
 *                "name": "..."
 *              },
 *              "note": null }
 *          ] }
 *      The `content.uri` field is a fully-qualified `otpauth://` URI, so
 *      we delegate to [OtpAuthEntry.parse] for each entry rather than
 *      re-parsing components — Proton has already encoded the canonical
 *      shape and our existing URI parser handles every case the QR path
 *      handles, including URL-encoded labels and SHA256/SHA512 algorithms.
 *      `content.name` is used to fill the account when the URI omits one
 *      (rare but observed for entries where the user added them manually
 *      without an account label).
 *
 *   3. **Generic flat OTP JSON** — third-party decoders (e.g. tools that
 *      convert Google Authenticator transfer QRs to JSON offline) emit a
 *      flatter per-entry schema:
 *        { "name": "...", "issuer": "...", "secret": "<base32>",
 *          "type": "totp" | "hotp", "period": 30, "digits": 6,
 *          "algorithm": "SHA1" | "SHA256" | "SHA512", "counter": 0 }
 *      Root may be `[...]` or `{"entries":[...]}` or `{"items":[...]}`.
 *      Each entry is parsed by extracting fields directly.
 *
 *   The two JSON shapes coexist within one parser: per entry we first try
 *   `content.uri` (Proton); if absent, we fall back to flat fields. Mixed
 *   files (some Proton entries + some flat) are also accepted.
 *
 * Output is a list of [OtpAuthEntry]. The caller materialises each into an
 * [AegisEntry] via [AegisEntry.fromOtpAuth] and dedupes against the existing
 * vault by `(issuer, account, secret bytes)`. Secrets are held in `ByteArray`
 * inside [OtpAuthEntry] and should be wiped after the vault save (see
 * [OtpAuthEntry.wipeSecret]).
 */
object FileImports {

    enum class Format { OTPAUTH_MIGRATION_URIS, PROTON_AUTH_JSON, GENERIC_OTP_JSON, UNKNOWN }

    data class ImportSummary(
        val entries: List<OtpAuthEntry>,
        val errors: List<String>,
        val multiBatchHint: String?,
    ) {
        val errorCount: Int get() = errors.size
    }

    /** Sniff format from the first chunk of the file. */
    fun detect(sample: String): Format {
        val trimmed = sample.trimStart()
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            // JSON path. Both Proton Authenticator and generic flat exports
            // dispatch to the same parser, which checks per-entry shape; for
            // detect() we just need to know "is this a JSON list of OTP
            // entries?" — distinguish Proton purely for the format-name
            // displayed in error messages.
            val lower = trimmed.take(2048).lowercase()
            return when {
                lower.contains("\"entry_type\"") ||
                    lower.contains("\"protonauth\"") ->
                    Format.PROTON_AUTH_JSON
                lower.contains("\"entries\"") ||
                    lower.contains("\"items\"") ||
                    lower.contains("\"secret\"") ->
                    Format.GENERIC_OTP_JSON
                else -> Format.UNKNOWN
            }
        }
        if (trimmed.lineSequence().any {
                it.trim().startsWith("otpauth-migration://", ignoreCase = true)
            }) return Format.OTPAUTH_MIGRATION_URIS
        return Format.UNKNOWN
    }

    /** Convenience entry point: read once, detect, dispatch. */
    fun parseAuto(reader: Reader): ImportSummary {
        val text = reader.readText()
        return when (detect(text.take(2048))) {
            Format.OTPAUTH_MIGRATION_URIS -> parseMigrationUris(text)
            Format.PROTON_AUTH_JSON -> parseProtonAuthJson(text)
            Format.GENERIC_OTP_JSON -> parseProtonAuthJson(text)
            Format.UNKNOWN -> throw IllegalArgumentException(
                "Unrecognised file. Expected one or more `otpauth-migration://` " +
                    "URIs (one per line), a Proton Authenticator JSON export, " +
                    "or a generic OTP JSON export."
            )
        }
    }

    /**
     * Parse a plain-text file whose lines are `otpauth-migration://` URIs.
     * Blank and comment lines (`#`-prefixed) are ignored. Each URI may
     * itself contain multiple TOTP entries (Google groups them per batch).
     */
    fun parseMigrationUris(text: String): ImportSummary {
        val entries = mutableListOf<OtpAuthEntry>()
        val errors = mutableListOf<String>()
        var multiBatchHint: String? = null
        for ((lineNum, raw) in text.lineSequence().withIndex()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            if (!GoogleAuthMigration.isMigrationUri(line)) {
                errors += "line ${lineNum + 1}: not an otpauth-migration:// URI"
                continue
            }
            try {
                val r = GoogleAuthMigration.parse(line)
                entries += r.entries
                if (r.isMultiBatch && multiBatchHint == null) {
                    multiBatchHint =
                        "Some URIs are multi-batch (this file contained batch ${r.batchIndex + 1}/${r.batchSize}). " +
                            "Make sure every batch is in the file or import the rest separately."
                }
            } catch (t: Throwable) {
                errors += "line ${lineNum + 1}: ${t.message ?: t.javaClass.simpleName}"
            }
        }
        return ImportSummary(entries, errors, multiBatchHint)
    }

    /**
     * Parse a Proton Authenticator JSON export, OR a generic OTP JSON dump
     * (root may be an array or `{"entries": [...]}`). Per-entry shape is the
     * same in both: name/issuer/secret/type/period/digits/algorithm/counter.
     */
    fun parseProtonAuthJson(text: String): ImportSummary {
        val trimmed = text.trim()
        val arr: JSONArray = when {
            trimmed.startsWith("[") -> JSONArray(trimmed)
            trimmed.startsWith("{") -> {
                val obj = JSONObject(trimmed)
                obj.optJSONArray("entries")
                    ?: obj.optJSONArray("items")
                    ?: throw IllegalArgumentException(
                        "JSON does not contain `entries` or `items` array."
                    )
            }
            else -> throw IllegalArgumentException("Not a JSON document.")
        }

        val entries = mutableListOf<OtpAuthEntry>()
        val errors = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i)
            if (o == null) {
                errors += "entry $i: not an object"
                continue
            }
            try {
                entries += parseOneJsonEntry(o)
            } catch (t: Throwable) {
                errors += "entry $i: ${t.message ?: t.javaClass.simpleName}"
            }
        }
        return ImportSummary(entries, errors, multiBatchHint = null)
    }

    // ---------- private helpers ----------

    private fun parseOneJsonEntry(o: JSONObject): OtpAuthEntry {
        // Proton Authenticator: `content.uri` is a complete otpauth:// URI.
        // Delegate to the canonical URI parser so we share the QR path's
        // semantics (URL-encoded labels, every algorithm/digit/period combo).
        val content = o.optJSONObject("content")
        if (content != null) {
            val uri = content.optString("uri")
            if (uri.isNotEmpty()) {
                val parsed = OtpAuthEntry.parse(uri)
                val displayName = content.optString("name")
                    .ifEmpty { o.optString("name") }
                // Only override if the URI lacked an account — never replace
                // a URI-supplied label with a Proton display name.
                return if (parsed.account.isEmpty() && displayName.isNotEmpty()) {
                    parsed.copy(account = displayName)
                } else {
                    parsed
                }
            }
        }

        // Generic flat schema: `secret` (base32) + companion fields.
        val secretStr = o.optString("secret")
            .ifEmpty { o.optString("seed") }
            .ifEmpty { o.optString("key") }
        require(secretStr.isNotEmpty()) { "missing `content.uri` or `secret`" }
        // Strip whitespace and dashes — Aegis/Proton/Google share a habit of
        // decorating displayed secrets that way.
        val cleaned = secretStr.replace("\\s+".toRegex(), "").replace("-", "")
        val secretBytes = HotpSecret.decodeBase32(cleaned)

        val type = when (o.optString("type", "totp").lowercase()) {
            "hotp" -> OtpAuthEntry.Type.HOTP
            else -> OtpAuthEntry.Type.TOTP
        }
        val algo = when (o.optString("algorithm", "SHA1").uppercase()) {
            "SHA256" -> OtpAuthEntry.Algorithm.SHA256
            "SHA512" -> OtpAuthEntry.Algorithm.SHA512
            else -> OtpAuthEntry.Algorithm.SHA1
        }
        val digits = o.optInt("digits", 6).let { if (it == 0) 6 else it }
        val period = o.optInt("period", 30).let { if (it == 0) 30 else it }
        val counter = o.optLong("counter", 0)
        val name = o.optString("name").ifEmpty { o.optString("account") }
        val issuer = o.optString("issuer")

        return OtpAuthEntry(
            type = type,
            issuer = issuer,
            account = name,
            secret = secretBytes,
            digits = digits,
            period = period,
            counter = counter,
            algorithm = algo,
        )
    }
}
