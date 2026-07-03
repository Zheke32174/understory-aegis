package com.understory.aegis

import com.understory.security.HotpSecret
import com.understory.security.OtpAuthEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class FileImportsTest {

    private val sampleSecretBase32 = HotpSecret.encodeBase32(
        ByteArray(20) { (it * 7 % 256).toByte() }
    )

    // ---------- detect ----------

    @Test
    fun detectsMigrationUriLine() {
        val text = "otpauth-migration://offline?data=ABCDE\nsome trailing"
        assertEquals(FileImports.Format.OTPAUTH_MIGRATION_URIS, FileImports.detect(text))
    }

    @Test
    fun detectsProtonAuthJson() {
        // Real Proton Authenticator backup shape: entries[].content.{uri,entry_type,name}.
        val text = """{"version":1,"entries":[{"id":"x","content":{"uri":"otpauth://totp/A?secret=$sampleSecretBase32&issuer=B","entry_type":"Totp","name":"A"},"note":null}]}"""
        assertEquals(FileImports.Format.PROTON_AUTH_JSON, FileImports.detect(text))
    }

    @Test
    fun detectsGenericJson() {
        val text = """[{"name":"X","secret":"$sampleSecretBase32"}]"""
        assertEquals(FileImports.Format.GENERIC_OTP_JSON, FileImports.detect(text))
    }

    @Test
    fun rejectsRandomText() {
        assertEquals(FileImports.Format.UNKNOWN, FileImports.detect("hello world"))
    }

    // ---------- migration URIs ----------

    @Test
    fun migrationUriParserCallsThroughToGoogleAuth() {
        // Use a synthetic but well-formed migration URI by reusing
        // GoogleAuthMigration's parser indirectly. We can't easily construct
        // the protobuf payload here, so build one with a single entry.
        val payload = encodeMigrationPayload(
            entries = listOf(OtpParam(
                secret = HotpSecret.decodeBase32(sampleSecretBase32),
                name = "alice@example.com",
                issuer = "Example",
                algorithm = 1, digits = 1, type = 2, counter = 0,
            )),
            batchSize = 1,
            batchIndex = 0,
        )
        val b64 = android.util.Base64.encodeToString(payload, android.util.Base64.NO_WRAP)
        val uri = "otpauth-migration://offline?data=${java.net.URLEncoder.encode(b64, "UTF-8")}"

        val text = "# comment line\n\n$uri\n"
        val summary = FileImports.parseMigrationUris(text)
        assertEquals(0, summary.errorCount)
        assertEquals(1, summary.entries.size)
        assertEquals("Example", summary.entries[0].issuer)
        assertEquals("alice@example.com", summary.entries[0].account)
    }

    @Test
    fun migrationUriToleratesSpaceInBase64Data() {
        // design §6 D-S6: a literal `+` in offline-decoded migration data becomes
        // a space via Uri.getQueryParameter. GoogleAuthMigration strips ASCII
        // whitespace before Base64.decode, so a data param with an embedded space
        // still parses. Build a valid payload, base64 it, inject a space, and
        // confirm the entry survives.
        val payload = encodeMigrationPayload(
            entries = listOf(OtpParam(
                secret = HotpSecret.decodeBase32(sampleSecretBase32),
                name = "sp", issuer = "Sp", algorithm = 1, digits = 1, type = 2, counter = 0,
            )),
            batchSize = 1, batchIndex = 0,
        )
        val b64 = android.util.Base64.encodeToString(payload, android.util.Base64.NO_WRAP)
        // Inject a raw space mid-string (the `+`→space symptom). URL-encode the
        // rest so getQueryParameter yields base64-with-a-space.
        val withSpace = b64.substring(0, 4) + " " + b64.substring(4)
        val uri = "otpauth-migration://offline?data=${java.net.URLEncoder.encode(withSpace, "UTF-8")}"
        val summary = FileImports.parseMigrationUris(uri)
        assertEquals(0, summary.errorCount)
        assertEquals(1, summary.entries.size)
        assertEquals("Sp", summary.entries[0].issuer)
    }

    @Test
    fun migrationUriParserFlagsBadLines() {
        val text = "otpauth-migration://offline?data=NOT_BASE64\nthis line isn't a uri"
        val summary = FileImports.parseMigrationUris(text)
        assertEquals(0, summary.entries.size)
        assertEquals(2, summary.errorCount)
    }

    // ---------- Proton Authenticator (real schema) ----------

    @Test
    fun protonAuthJsonHappyPath() {
        // Mirrors the real Proton backup shape: each entry has
        // {id, content:{uri, entry_type, name}, note}. The uri is a complete
        // otpauth:// URI we round-trip through OtpAuthEntry.parse.
        val json = """
{
  "version": 1,
  "entries": [
    { "id": "abc",
      "content": {
        "uri": "otpauth://totp/zheke32174?secret=$sampleSecretBase32&issuer=PyPI&algorithm=SHA1&digits=6&period=30",
        "entry_type": "Totp",
        "name": "zheke32174"
      },
      "note": null },
    { "id": "def",
      "content": {
        "uri": "otpauth://totp/nitro?secret=$sampleSecretBase32&issuer=nitrokey&algorithm=SHA256&digits=6&period=30",
        "entry_type": "Totp",
        "name": "nitro"
      },
      "note": null }
  ]
}
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(0, summary.errorCount)
        assertEquals(2, summary.entries.size)

        val first = summary.entries[0]
        assertEquals("PyPI", first.issuer)
        assertEquals("zheke32174", first.account)
        assertEquals(OtpAuthEntry.Type.TOTP, first.type)
        assertEquals(30, first.period)
        assertEquals(6, first.digits)
        assertEquals(OtpAuthEntry.Algorithm.SHA1, first.algorithm)

        val second = summary.entries[1]
        assertEquals("nitrokey", second.issuer)
        assertEquals("nitro", second.account)
        assertEquals(OtpAuthEntry.Algorithm.SHA256, second.algorithm)
    }

    @Test
    fun protonAuthJsonHandlesUrlEncodedAccount() {
        // Real-world example: account is `zheke32174@gmail.com` URL-encoded
        // in the URI label.
        val json = """
{"version":1,"entries":[
  {"id":"x","content":{"uri":"otpauth://totp/zheke32174%40gmail.com?secret=$sampleSecretBase32&issuer=OpenAI&algorithm=SHA1&digits=6&period=30","entry_type":"Totp","name":"zheke32174@gmail.com"},"note":null}
]}
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(1, summary.entries.size)
        assertEquals("OpenAI", summary.entries[0].issuer)
        assertEquals("zheke32174@gmail.com", summary.entries[0].account)
    }

    @Test
    fun protonAuthJsonFallsBackToContentNameWhenUriLacksAccount() {
        // Constructed: URI's label is generic (no account) and the issuer
        // param is empty, but content.name has the human-readable label.
        val json = """
{"version":1,"entries":[
  {"id":"x","content":{"uri":"otpauth://totp/?secret=$sampleSecretBase32&issuer=&algorithm=SHA1&digits=6&period=30","entry_type":"Totp","name":"display-name"},"note":null}
]}
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(1, summary.entries.size)
        assertEquals("display-name", summary.entries[0].account)
    }

    @Test
    fun protonAuthJsonHandlesPlusEncodedSpacesInSecret() {
        // Real-world example from the user's backup: secret param has `+`
        // separators which Uri.getQueryParameter decodes to spaces.
        // HotpSecret.decodeBase32 tolerates whitespace and case, so the
        // round-trip should still produce a valid byte secret.
        val raw = "2Z3MMH6PZEA4AAP6LSDBGZWMH656WIUK"
        val plusSeparated = raw.chunked(4).joinToString("+")
        val json = """
{"version":1,"entries":[
  {"id":"x","content":{"uri":"otpauth://totp/admin?secret=$plusSeparated&issuer=googleadmin&algorithm=SHA1&digits=6&period=30","entry_type":"Totp","name":"admin"},"note":null}
]}
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(0, summary.errorCount)
        assertEquals(1, summary.entries.size)
        // Re-encoding the parsed bytes should yield the canonical (no-spaces) form.
        val roundTripped = HotpSecret.encodeBase32(summary.entries[0].secret)
        assertEquals(raw, roundTripped)
    }

    @Test
    fun protonAuthJsonIgnoresContentNameWhenUriHasAccount() {
        // Confirms we don't clobber URI-supplied account labels with
        // content.name (which can drift from the URI).
        val json = """
{"version":1,"entries":[
  {"id":"x","content":{"uri":"otpauth://totp/from-uri?secret=$sampleSecretBase32&issuer=I&algorithm=SHA1&digits=6&period=30","entry_type":"Totp","name":"different-name"},"note":null}
]}
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(1, summary.entries.size)
        assertEquals("from-uri", summary.entries[0].account)
    }

    // ---------- Generic flat OTP JSON ----------

    @Test
    fun genericJsonAcceptsBareArray() {
        val json = """
[
  { "account": "alice", "secret": "$sampleSecretBase32" }
]
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(1, summary.entries.size)
        // `account` falls back when `name` is absent.
        assertEquals("alice", summary.entries[0].account)
        // Defaults used when fields omitted.
        assertEquals(OtpAuthEntry.Type.TOTP, summary.entries[0].type)
        assertEquals(30, summary.entries[0].period)
        assertEquals(6, summary.entries[0].digits)
    }

    @Test
    fun genericJsonAcceptsItemsKey() {
        val json = """
{ "items": [
  { "name": "alice", "secret": "$sampleSecretBase32" }
]}
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(1, summary.entries.size)
    }

    @Test
    fun jsonStripsWhitespaceFromSecrets() {
        val displayed = sampleSecretBase32
            .chunked(4)
            .joinToString(" ")
        val json = """[{"name":"a","secret":"$displayed"}]"""
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(1, summary.entries.size)
        // Round-trips back to the canonical base32 by re-encoding bytes.
        val roundTripped = HotpSecret.encodeBase32(summary.entries[0].secret)
        assertEquals(sampleSecretBase32, roundTripped)
    }

    @Test
    fun jsonReportsPerEntryErrorsButContinues() {
        val json = """
[
  { "name": "good",  "secret": "$sampleSecretBase32" },
  { "name": "bad" },
  { "name": "alsoGood", "secret": "$sampleSecretBase32" }
]
        """.trimIndent()
        val summary = FileImports.parseProtonAuthJson(json)
        assertEquals(2, summary.entries.size)
        assertEquals(1, summary.errorCount)
        assertTrue(summary.errors[0].contains("entry 1"))
    }

    // ---------- Aegis Authenticator (real schema, design §3.2) ----------

    @Test
    fun detectsAegisAuthJson() {
        val text = """{"version":1,"header":{"slots":null,"params":null},"db":{"version":3,"entries":[{"type":"totp","name":"a","issuer":"I","info":{"secret":"$sampleSecretBase32","algo":"SHA1","digits":6,"period":30}}]}}"""
        assertEquals(FileImports.Format.AEGIS_AUTH_JSON, FileImports.detect(text))
    }

    @Test
    fun aegisAuthJsonHappyPath() {
        val json = """
{"version":1,"header":{"slots":null,"params":null},"db":{"version":3,"entries":[
  {"type":"totp","uuid":"1","name":"alice","issuer":"PyPI","note":"","info":{"secret":"$sampleSecretBase32","algo":"SHA256","digits":8,"period":60}},
  {"type":"hotp","uuid":"2","name":"bob","issuer":"GitHub","note":"","info":{"secret":"$sampleSecretBase32","algo":"SHA1","digits":6,"counter":5}}
]}}
        """.trimIndent()
        val summary = FileImports.parseAegisAuthJson(json)
        assertEquals(0, summary.errorCount)
        assertEquals(2, summary.entries.size)

        val totp = summary.entries[0]
        assertEquals("PyPI", totp.issuer)
        assertEquals("alice", totp.account)
        assertEquals(OtpAuthEntry.Type.TOTP, totp.type)
        assertEquals(OtpAuthEntry.Algorithm.SHA256, totp.algorithm)
        assertEquals(8, totp.digits)
        assertEquals(60, totp.period)

        val hotp = summary.entries[1]
        assertEquals(OtpAuthEntry.Type.HOTP, hotp.type)
        assertEquals(5L, hotp.counter)
    }

    @Test
    fun aegisAuthJsonRejectsSteamPerEntryButKeepsOthers() {
        val json = """
{"version":1,"header":{"slots":null,"params":null},"db":{"version":3,"entries":[
  {"type":"steam","uuid":"1","name":"s","issuer":"Steam","info":{"secret":"$sampleSecretBase32","algo":"SHA1","digits":5,"period":30}},
  {"type":"totp","uuid":"2","name":"ok","issuer":"OK","info":{"secret":"$sampleSecretBase32","algo":"SHA1","digits":6,"period":30}}
]}}
        """.trimIndent()
        val summary = FileImports.parseAegisAuthJson(json)
        assertEquals(1, summary.entries.size)
        assertEquals(1, summary.errorCount)
        assertTrue(summary.errors[0].contains("Steam"))
    }

    @Test
    fun aegisAuthJsonRejectsEncryptedVault() {
        val json = """
{"version":1,"header":{"slots":[{"type":1,"n":32768}],"params":{"nonce":"aa","tag":"bb"}},"db":"ENCRYPTED_BLOB"}
        """.trimIndent()
        try {
            FileImports.parseAegisAuthJson(json)
            fail("expected encrypted-vault rejection")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("encrypted Aegis vault"))
        }
    }

    @Test
    fun aegisAuthJson_roundTripsThroughExporter() {
        // Both directions must pass (design §3.3): export our entries to Aegis
        // JSON, re-import, and confirm params survive.
        val entries = listOf(
            AegisEntry(
                issuer = "PyPI", account = "alice",
                secretB64 = android.util.Base64.encodeToString(
                    HotpSecret.decodeBase32(sampleSecretBase32), android.util.Base64.NO_WRAP,
                ),
                type = OtpAuthEntry.Type.TOTP, digits = 8, period = 60,
                algorithm = OtpAuthEntry.Algorithm.SHA512,
            ),
            AegisEntry(
                issuer = "GitHub", account = "bob",
                secretB64 = android.util.Base64.encodeToString(
                    HotpSecret.decodeBase32(sampleSecretBase32), android.util.Base64.NO_WRAP,
                ),
                type = OtpAuthEntry.Type.HOTP, digits = 6, counter = 7,
                algorithm = OtpAuthEntry.Algorithm.SHA1,
            ),
        )
        val exported = AegisAuthExport.toAegisJson(entries)
        assertEquals(FileImports.Format.AEGIS_AUTH_JSON, FileImports.detect(exported))
        val summary = FileImports.parseAegisAuthJson(exported)
        assertEquals(0, summary.errorCount)
        assertEquals(2, summary.entries.size)
        assertEquals(OtpAuthEntry.Algorithm.SHA512, summary.entries[0].algorithm)
        assertEquals(8, summary.entries[0].digits)
        assertEquals(60, summary.entries[0].period)
        assertEquals(OtpAuthEntry.Type.HOTP, summary.entries[1].type)
        assertEquals(7L, summary.entries[1].counter)
    }

    @Test
    fun aegisAuthJson_detectPrecedesGenericEntriesBranch() {
        // The generic branch keys on "entries"; the Aegis branch must win so the
        // db.entries[].info shape isn't swallowed and silently failed.
        val text = """{"version":1,"db":{"entries":[{"type":"totp","name":"a","info":{"secret":"$sampleSecretBase32"}}]}}"""
        assertEquals(FileImports.Format.AEGIS_AUTH_JSON, FileImports.detect(text))
    }

    // ---------- parseAuto ----------

    @Test
    fun parseAutoDispatchesByDetect() {
        val json = """[{"name":"a","secret":"$sampleSecretBase32"}]"""
        val summary = FileImports.parseAuto(json.reader())
        assertEquals(1, summary.entries.size)
    }

    @Test
    fun parseAutoThrowsOnUnknown() {
        try {
            FileImports.parseAuto("definitely not a recognised export".reader())
            fail("expected unknown-format rejection")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("Unrecognised"))
        }
    }

    @Test
    fun summaryHasNoMultiBatchHintForSingleBatch() {
        val payload = encodeMigrationPayload(
            entries = listOf(OtpParam(
                secret = HotpSecret.decodeBase32(sampleSecretBase32),
                name = "x", issuer = "Y", algorithm = 1, digits = 1, type = 2, counter = 0,
            )),
            batchSize = 1, batchIndex = 0,
        )
        val b64 = android.util.Base64.encodeToString(payload, android.util.Base64.NO_WRAP)
        val uri = "otpauth-migration://offline?data=${java.net.URLEncoder.encode(b64, "UTF-8")}"
        val summary = FileImports.parseMigrationUris(uri)
        assertNull(summary.multiBatchHint)
    }

    @Test
    fun summaryHasMultiBatchHintForBatchedExports() {
        val payload = encodeMigrationPayload(
            entries = listOf(OtpParam(
                secret = HotpSecret.decodeBase32(sampleSecretBase32),
                name = "x", issuer = "Y", algorithm = 1, digits = 1, type = 2, counter = 0,
            )),
            batchSize = 3, batchIndex = 0,
        )
        val b64 = android.util.Base64.encodeToString(payload, android.util.Base64.NO_WRAP)
        val uri = "otpauth-migration://offline?data=${java.net.URLEncoder.encode(b64, "UTF-8")}"
        val summary = FileImports.parseMigrationUris(uri)
        assertNotNull(summary.multiBatchHint)
        assertTrue(summary.multiBatchHint!!.contains("1/3"))
    }

    // ---------- helpers: protobuf encoder for migration test fixtures ----------

    private data class OtpParam(
        val secret: ByteArray, val name: String, val issuer: String,
        val algorithm: Int, val digits: Int, val type: Int, val counter: Long,
    )

    private fun encodeMigrationPayload(
        entries: List<OtpParam>, batchSize: Int, batchIndex: Int,
    ): ByteArray {
        val buf = java.io.ByteArrayOutputStream()
        for (e in entries) {
            val sub = java.io.ByteArrayOutputStream()
            writeLenDelimited(sub, 1, e.secret)
            writeLenDelimited(sub, 2, e.name.toByteArray())
            writeLenDelimited(sub, 3, e.issuer.toByteArray())
            writeVarint(sub, 4, e.algorithm.toLong())
            writeVarint(sub, 5, e.digits.toLong())
            writeVarint(sub, 6, e.type.toLong())
            writeVarint(sub, 7, e.counter)
            writeLenDelimited(buf, 1, sub.toByteArray())
        }
        writeVarint(buf, 2, 1L)            // version
        writeVarint(buf, 3, batchSize.toLong())
        writeVarint(buf, 4, batchIndex.toLong())
        writeVarint(buf, 5, 0L)            // batch_id
        return buf.toByteArray()
    }

    private fun writeVarint(out: java.io.ByteArrayOutputStream, fieldNumber: Int, v: Long) {
        writeRawVarint(out, ((fieldNumber shl 3) or 0).toLong())
        writeRawVarint(out, v)
    }

    private fun writeLenDelimited(out: java.io.ByteArrayOutputStream, fieldNumber: Int, b: ByteArray) {
        writeRawVarint(out, ((fieldNumber shl 3) or 2).toLong())
        writeRawVarint(out, b.size.toLong())
        out.write(b)
    }

    private fun writeRawVarint(out: java.io.ByteArrayOutputStream, value: Long) {
        var v = value
        while ((v and 0x7FL.inv()) != 0L) {
            out.write(((v and 0x7FL) or 0x80L).toInt())
            v = v ushr 7
        }
        out.write((v and 0x7FL).toInt())
    }
}
