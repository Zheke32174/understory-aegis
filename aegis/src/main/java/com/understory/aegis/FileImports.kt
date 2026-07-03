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
 *   2. **Proton Authenticator JSON export** — the exact schema Proton's
 *      Rust core (`proton-pass-common`, `AuthenticatorEntriesExport`) emits
 *      for an *unencrypted* export:
 *        { "version": 1,
 *          "entries": [
 *            { "id": "<uuid>",
 *              "content": {
 *                "uri": "otpauth://totp/<label>?secret=...&issuer=...&...",
 *                "entry_type": "Totp",           // serde enum, exactly "Totp" | "Steam"
 *                "name": "..."                   // Option<String>, may be null
 *              },
 *              "note": null }                    // Option<String>, may be null
 *          ] }
 *      Notes verified against Proton's source:
 *        - `entry_type` is a serde-serialized enum with only two variants,
 *          the exact strings `"Totp"` and `"Steam"` (PascalCase, no rename).
 *        - For a TOTP entry `content.uri` is a fully-qualified `otpauth://totp/`
 *          URI: Proton puts the account in the path and the issuer in the
 *          `issuer=` query param (it does NOT emit the `Issuer:Account` label
 *          form), plus explicit `algorithm`/`digits`/`period`. We delegate to
 *          [OtpAuthEntry.parse]; our URI parser already handles issuer-param
 *          precedence, URL-encoded labels, and SHA256/SHA512.
 *        - For a STEAM entry `content.uri` is `steam://<secret>` (NOT otpauth)
 *          and `entry_type` is `"Steam"`. Steam codes use a custom 5-char
 *          alphabet truncation, NOT RFC-6238 digit truncation, so aegis's
 *          standard generator ([AegisCode]) cannot reproduce them. We reject
 *          Steam entries per-entry with an honest message rather than importing
 *          a look-alike that would silently generate wrong codes.
 *        - Proton has NO HOTP entries (only Totp and Steam).
 *      `content.name` is used to fill the account only when the URI omits one.
 *
 *      **Encrypted Proton export** — a password-protected export is a different
 *      top-level shape: `{ "version": 1, "salt": "<b64>", "content": "<b64>" }`
 *      (Argon2id + AES-GCM; the encrypted entries live inside `content`). It has
 *      NO `entries` array. We cannot decrypt it (no passphrase-prompt UI and no
 *      Argon2id on our classpath here), so we detect it up front and refuse with
 *      a clear, actionable message telling the user to re-export unencrypted.
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

    /**
     * Shown when the user picks an *encrypted* (password-protected) Proton
     * Authenticator export. We cannot decrypt it here, so the honest action is
     * to re-export without a password. Matches the tone of the encrypted-Aegis
     * rejection in [parseAegisAuthJson].
     */
    private const val ENCRYPTED_PROTON_MESSAGE: String =
        "This is an encrypted (password-protected) Proton Authenticator export. " +
            "Understory OTP can't decrypt it. In Proton Authenticator, export again " +
            "WITHOUT a password (the unencrypted JSON option), then import that file."

    enum class Format {
        OTPAUTH_MIGRATION_URIS,
        AEGIS_AUTH_JSON,
        PROTON_AUTH_JSON,
        PROTON_ENCRYPTED_JSON,
        GENERIC_OTP_JSON,
        UNKNOWN,
    }

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
        if (trimmed.startsWith("{")) {
            // Encrypted-Proton check FIRST. Two tiers so it works whether or not
            // the (possibly truncated 2048-char) sample is parseable JSON:
            //   1. If the whole sample parses, confirm structurally — top-level
            //      `salt` string + `content` STRING + NO `entries` array. This
            //      avoids the false-positive where unencrypted Proton has a
            //      `content` OBJECT per entry.
            //   2. If it does NOT parse (the encrypted `content` base64 is long
            //      and gets cut off mid-string), fall back to top-level key
            //      markers: a `"salt"` key AND a `"content"` key but NO
            //      `"entries"`/`"entry_type"`/`"items"` — the encrypted shape is
            //      the only Proton export carrying a top-level `salt`.
            val parsed = runCatching { JSONObject(trimmed) }.getOrNull()
            if (parsed != null) {
                val hasSaltStr = parsed.optString("salt", "").isNotEmpty()
                val hasContentStr = parsed.opt("content") is String &&
                    parsed.optString("content", "").isNotEmpty()
                val hasEntriesArr = parsed.optJSONArray("entries") != null
                if (hasSaltStr && hasContentStr && !hasEntriesArr) {
                    return Format.PROTON_ENCRYPTED_JSON
                }
            } else {
                val lower = trimmed.take(2048).lowercase()
                val looksEncrypted = lower.contains("\"salt\"") &&
                    lower.contains("\"content\"") &&
                    !lower.contains("\"entries\"") &&
                    !lower.contains("\"entry_type\"") &&
                    !lower.contains("\"items\"")
                if (looksEncrypted) return Format.PROTON_ENCRYPTED_JSON
            }
        }
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            // JSON path. Both Proton Authenticator and generic flat exports
            // dispatch to the same parser, which checks per-entry shape; for
            // detect() we just need to know "is this a JSON list of OTP
            // entries?" — distinguish Proton purely for the format-name
            // displayed in error messages.
            val lower = trimmed.take(2048).lowercase()
            return when {
                // Real Aegis Authenticator: entries live under `db.entries[]`
                // with per-entry `info`. Checked FIRST — the generic `"entries"`
                // branch below would otherwise swallow it and then fail (the
                // array is under `db`, and each secret is under `info.secret`).
                lower.contains("\"db\"") && lower.contains("\"info\"") ->
                    Format.AEGIS_AUTH_JSON
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
            Format.AEGIS_AUTH_JSON -> parseAegisAuthJson(text)
            Format.PROTON_AUTH_JSON -> parseProtonAuthJson(text)
            Format.PROTON_ENCRYPTED_JSON -> throw IllegalArgumentException(ENCRYPTED_PROTON_MESSAGE)
            Format.GENERIC_OTP_JSON -> parseProtonAuthJson(text)
            Format.UNKNOWN -> throw IllegalArgumentException(
                "Unrecognised file. Expected one or more `otpauth-migration://` " +
                    "URIs (one per line), an Aegis Authenticator JSON export, a " +
                    "Proton Authenticator JSON export, or a generic OTP JSON export."
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
                // Defense in depth: if an encrypted Proton export reaches this
                // parser directly (a detect() miss on a truncated sample, or a
                // direct call), refuse with the same honest message rather than
                // the generic "no entries/items" error below.
                if (obj.optString("salt", "").isNotEmpty() &&
                    obj.opt("content") is String &&
                    obj.optJSONArray("entries") == null
                ) {
                    throw IllegalArgumentException(ENCRYPTED_PROTON_MESSAGE)
                }
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

    /**
     * Parse a real Aegis Authenticator plaintext export (design §3.2). Entries
     * live under `db.entries[]`; each carries `type`, root `name`/`issuer`, and
     * an `info` object holding `secret` (base32), `algo`, `digits`, and either
     * `period` (TOTP) or `counter` (HOTP).
     *
     * Boundaries surfaced honestly rather than silently mishandled:
     *   - `header.slots != null` → the vault is ENCRYPTED (scrypt key-slots +
     *     AES-GCM db). One clear error; decrypt is a tracked v1.5 item.
     *   - `type == "steam"` → per-entry error (Steam's truncation differs; do
     *     NOT import it as TOTP).
     */
    fun parseAegisAuthJson(text: String): ImportSummary {
        val root = JSONObject(text.trim())

        // Encrypted Aegis vault: header.slots is a populated array. Refuse with
        // a clear, actionable message instead of a downstream parse failure.
        val header = root.optJSONObject("header")
        if (header != null && !header.isNull("slots") && header.optJSONArray("slots") != null) {
            throw IllegalArgumentException(
                "This is an encrypted Aegis vault. In Aegis Authenticator, export an " +
                    "*unencrypted* JSON, or use a password-encrypted Understory backup."
            )
        }

        val db = root.optJSONObject("db")
            ?: throw IllegalArgumentException("Aegis export missing `db` object.")
        val arr = db.optJSONArray("entries") ?: JSONArray()

        val entries = mutableListOf<OtpAuthEntry>()
        val errors = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i)
            if (o == null) {
                errors += "entry $i: not an object"
                continue
            }
            try {
                entries += parseOneAegisEntry(o)
            } catch (t: Throwable) {
                errors += "entry $i: ${t.message ?: t.javaClass.simpleName}"
            }
        }
        return ImportSummary(entries, errors, multiBatchHint = null)
    }

    // ---------- private helpers ----------

    private fun parseOneAegisEntry(o: JSONObject): OtpAuthEntry {
        val type = when (o.optString("type", "totp").lowercase()) {
            "totp" -> OtpAuthEntry.Type.TOTP
            "hotp" -> OtpAuthEntry.Type.HOTP
            "steam" -> throw IllegalArgumentException(
                "Steam OTP not supported (its code truncation differs from standard TOTP)."
            )
            else -> throw IllegalArgumentException("unknown Aegis entry type")
        }
        val info = o.optJSONObject("info")
            ?: throw IllegalArgumentException("missing `info`")
        val secretStr = info.optString("secret")
        require(secretStr.isNotEmpty()) { "missing `info.secret`" }
        val secretBytes = HotpSecret.decodeBase32(secretStr)

        val algo = when (info.optString("algo", "SHA1").uppercase()) {
            "SHA256" -> OtpAuthEntry.Algorithm.SHA256
            "SHA512" -> OtpAuthEntry.Algorithm.SHA512
            else -> OtpAuthEntry.Algorithm.SHA1
        }
        val digits = info.optInt("digits", 6).let { if (it == 0) 6 else it }
        val period = info.optInt("period", 30).let { if (it == 0) 30 else it }
        val counter = info.optLong("counter", 0)

        return OtpAuthEntry(
            type = type,
            issuer = o.optString("issuer"),
            account = o.optString("name"),
            secret = secretBytes,
            digits = digits,
            period = period,
            counter = counter,
            algorithm = algo,
        )
    }

    private fun parseOneJsonEntry(o: JSONObject): OtpAuthEntry {
        // Proton Authenticator: entry is `{ id, content:{uri, entry_type, name}, note }`.
        val content = o.optJSONObject("content")
        if (content != null) {
            val uri = content.optString("uri")
            // Proton's `entry_type` is the serde enum "Totp" | "Steam". Branch
            // on it (and on the URI scheme) so a Steam entry is rejected with an
            // honest message instead of being fed to the otpauth parser — which
            // would either throw a cryptic "not an otpauth URI" or, worse, get
            // coerced into a standard-TOTP look-alike that generates codes Steam
            // rejects. Steam's 5-char alphabet truncation is NOT representable by
            // aegis's RFC-6238 generator, so we refuse rather than mis-import.
            val entryType = content.optString("entry_type").trim()
            val isSteam = entryType.equals("Steam", ignoreCase = true) ||
                uri.trim().startsWith("steam://", ignoreCase = true)
            if (isSteam) {
                throw IllegalArgumentException(
                    "Steam entry not supported: Steam codes use a custom 5-character " +
                        "alphabet, not standard TOTP digits, so this app can't generate " +
                        "them. Keep this account in Proton Authenticator or Steam Guard."
                )
            }
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
            // A Proton `content` object with an empty/absent uri is malformed —
            // surface it honestly rather than silently falling through to the
            // flat-schema branch (which would then report a misleading "missing
            // secret").
            throw IllegalArgumentException("Proton entry `content.uri` is empty")
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
