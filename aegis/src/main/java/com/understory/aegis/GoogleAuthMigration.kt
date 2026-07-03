package com.understory.aegis

import android.net.Uri
import android.util.Base64
import com.understory.security.OtpAuthEntry

/**
 * Parser for Google Authenticator's "Transfer accounts" export QR.
 *
 * Google Authenticator emits QR codes of the form:
 *
 *   otpauth-migration://offline?data=<URL-encoded base64 of MigrationPayload>
 *
 * The base64 decodes to a Google-defined protobuf (MigrationPayload):
 *
 *   message MigrationPayload {
 *     repeated OtpParameters otp_parameters = 1;
 *     int32 version = 2;
 *     int32 batch_size = 3;
 *     int32 batch_index = 4;
 *     int32 batch_id = 5;
 *   }
 *   message OtpParameters {
 *     bytes secret = 1;
 *     string name = 2;
 *     string issuer = 3;
 *     Algorithm algorithm = 4;  // 0=unspec 1=SHA1 2=SHA256 3=SHA512 4=MD5
 *     DigitCount digits = 5;    // 0=unspec 1=SIX 2=EIGHT
 *     OtpType type = 6;         // 0=unspec 1=HOTP 2=TOTP
 *     int64 counter = 7;
 *   }
 *
 * We implement a minimal protobuf wire-format reader inline (no deps)
 * and extract every OtpParameters as an [OtpAuthEntry].
 *
 * Limitations:
 *   - Single-batch only. If the user has too many accounts, Google emits
 *     multiple QRs (batch_size > 1). The user has to import them
 *     sequentially. We surface a "this is batch X of N" message so they
 *     know to come back with the next QR.
 *   - We ignore counter for HOTP (we display TOTP-style).
 */
object GoogleAuthMigration {

    /** Wire types per protobuf spec. */
    private const val WIRE_VARINT = 0
    private const val WIRE_LEN_DELIMITED = 2

    data class ImportResult(
        val entries: List<OtpAuthEntry>,
        val batchIndex: Int,
        val batchSize: Int,
    ) {
        val isMultiBatch: Boolean get() = batchSize > 1
    }

    /**
     * Returns true if [s] looks like a Google Authenticator export URI.
     */
    fun isMigrationUri(s: String): Boolean =
        s.trim().startsWith("otpauth-migration://", ignoreCase = true)

    /**
     * Parse a Google Auth migration QR string. Throws on malformed input.
     */
    fun parse(uriStr: String): ImportResult {
        val uri = Uri.parse(uriStr)
        require(uri.scheme.equals("otpauth-migration", ignoreCase = true)) {
            "not a Google Auth migration URI"
        }
        val dataParam = uri.getQueryParameter("data")
            ?: throw IllegalArgumentException("missing data parameter")
        // Google's URI is URL-encoded base64; android.net.Uri already
        // decodes the percent-encoding. The result is bare base64 (which
        // may contain + and / and = padding).
        val payload = Base64.decode(dataParam, Base64.DEFAULT)
        return parsePayload(payload)
    }

    private fun parsePayload(blob: ByteArray): ImportResult {
        val entries = mutableListOf<OtpAuthEntry>()
        var batchIndex = 0
        var batchSize = 1
        val reader = ProtoReader(blob)
        while (reader.hasMore()) {
            val (fieldNumber, wireType) = reader.readTag()
            when (fieldNumber) {
                1 -> {
                    require(wireType == WIRE_LEN_DELIMITED)
                    val sub = reader.readLenDelimited()
                    entries += parseOtpParameters(sub)
                }
                2 -> { reader.readVarint() /* version */ }
                3 -> {
                    require(wireType == WIRE_VARINT)
                    batchSize = reader.readVarint().toInt()
                }
                4 -> {
                    require(wireType == WIRE_VARINT)
                    batchIndex = reader.readVarint().toInt()
                }
                5 -> { reader.readVarint() /* batch_id */ }
                else -> reader.skip(wireType)
            }
        }
        return ImportResult(entries, batchIndex, batchSize)
    }

    private fun parseOtpParameters(blob: ByteArray): OtpAuthEntry {
        var secret = ByteArray(0)
        var name = ""
        var issuer = ""
        var algorithm = OtpAuthEntry.Algorithm.SHA1
        var digits = 6
        var type = OtpAuthEntry.Type.TOTP
        var counter = 0L

        val reader = ProtoReader(blob)
        while (reader.hasMore()) {
            val (fieldNumber, wireType) = reader.readTag()
            when (fieldNumber) {
                1 -> { secret = reader.readLenDelimited() }
                2 -> { name = String(reader.readLenDelimited(), Charsets.UTF_8) }
                3 -> { issuer = String(reader.readLenDelimited(), Charsets.UTF_8) }
                4 -> {
                    algorithm = when (reader.readVarint().toInt()) {
                        2 -> OtpAuthEntry.Algorithm.SHA256
                        3 -> OtpAuthEntry.Algorithm.SHA512
                        else -> OtpAuthEntry.Algorithm.SHA1
                    }
                }
                5 -> {
                    digits = when (reader.readVarint().toInt()) {
                        2 -> 8
                        else -> 6  // covers 0=unspec and 1=SIX
                    }
                }
                6 -> {
                    type = when (reader.readVarint().toInt()) {
                        1 -> OtpAuthEntry.Type.HOTP
                        else -> OtpAuthEntry.Type.TOTP  // covers 0=unspec and 2=TOTP
                    }
                }
                7 -> { counter = reader.readVarint() }
                else -> reader.skip(wireType)
            }
        }

        return OtpAuthEntry(
            type = type,
            issuer = issuer,
            account = name,
            secret = secret,
            digits = digits,
            period = 30,
            counter = counter,
            algorithm = algorithm,
        )
    }

    /** Minimal protobuf wire-format reader. */
    private class ProtoReader(private val buf: ByteArray) {
        private var pos = 0

        fun hasMore(): Boolean = pos < buf.size

        fun readTag(): Pair<Int, Int> {
            val tag = readVarint().toInt()
            val fieldNumber = tag ushr 3
            val wireType = tag and 0x07
            return fieldNumber to wireType
        }

        fun readVarint(): Long {
            var result = 0L
            var shift = 0
            while (pos < buf.size) {
                val b = buf[pos].toInt() and 0xFF
                pos++
                result = result or ((b and 0x7F).toLong() shl shift)
                if ((b and 0x80) == 0) return result
                shift += 7
                if (shift > 63) throw IllegalArgumentException("varint too long")
            }
            throw IllegalArgumentException("truncated varint")
        }

        fun readLenDelimited(): ByteArray {
            val len = readVarint().toInt()
            // Bound check expressed as `len in 0..(buf.size - pos)` instead
            // of `pos + len <= buf.size` to avoid integer overflow when
            // `len` is near Int.MAX_VALUE — the additive form silently
            // wraps to negative and falsely passes the bound check, then
            // copyOfRange throws an obscure IllegalArgumentException.
            require(len in 0..(buf.size - pos)) { "truncated length-delimited" }
            val out = buf.copyOfRange(pos, pos + len)
            pos += len
            return out
        }

        fun skip(wireType: Int) {
            when (wireType) {
                WIRE_VARINT -> readVarint()
                WIRE_LEN_DELIMITED -> {
                    // Inline length-only path. readLenDelimited() would
                    // allocate ByteArray(len) + copyOfRange, wasteful for
                    // a field we're discarding. A hostile QR with a 10 MB
                    // unknown field shouldn't force a 10 MB allocation
                    // just to skip past it.
                    val len = readVarint().toInt()
                    require(len in 0..(buf.size - pos)) { "truncated length-delimited" }
                    pos += len
                }
                1 -> pos += 8  // 64-bit fixed
                5 -> pos += 4  // 32-bit fixed
                else -> throw IllegalArgumentException("unsupported wire type: $wireType")
            }
        }
    }
}
