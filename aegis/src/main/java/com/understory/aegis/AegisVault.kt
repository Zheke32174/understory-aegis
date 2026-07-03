package com.understory.aegis

import android.annotation.SuppressLint
import android.content.Context
import com.understory.security.Crypto
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Aegis's vault file format. Parallels passgen's structure exactly so the
 * suite has one mental model:
 *
 *   [ 1 byte    ] version (= 1)
 *   [ 4 byte BE ] device-auth wrapped-KEK IV length
 *   [ N bytes   ] wrapped-KEK IV
 *   [ 4 byte BE ] device-auth wrapped-KEK ciphertext length
 *   [ N bytes   ] wrapped-KEK ciphertext (32 bytes plaintext, AES-256-GCM
 *                 wrapped under a Keystore key gated by BiometricPrompt)
 *   [ 4 byte BE ] content-cipher length
 *   [ N bytes   ] AES-256-GCM(entries_json, KEK)
 *
 * The KEK is 32 random bytes — the symmetric vault key. It only exists in
 * memory between BiometricPrompt success and `lock()`. The Keystore copy
 * is what daily unlock uses; cannot leave Keystore.
 *
 * Snake-eats-tail: the master KEK is also stored as the vault's first
 * entry (for paper transcription / disaster recovery), same pattern as
 * passgen.
 */
object AegisVault {

    private const val FILE = "aegis-vault.bin"
    private const val VERSION_V1: Byte = 1

    /** 32-byte symmetric KEK — same size as passgen. */
    private const val MASTER_KEK_BYTES = 32

    fun exists(ctx: Context): Boolean = File(ctx.filesDir, FILE).exists()

    /**
     * Sweep an orphaned `*.tmp` file left by a process kill mid-write.
     * Called from the vault entry points before any read or write — the
     * real vault file is untouched until atomic rename, so the tmp is
     * pure garbage. Without this sweep, repeated interrupted writes
     * accumulate orphan tmps over time.
     */
    private fun sweepTmp(ctx: Context) {
        runCatching { File(ctx.filesDir, "$FILE.tmp").delete() }
    }

    fun delete(ctx: Context) {
        File(ctx.filesDir, FILE).delete()
        Crypto.deleteDeviceAuthKey()
    }

    /** Read the IV needed to construct the unlock cipher. */
    fun ivForUnlock(ctx: Context): ByteArray = readFile(ctx).first.wrappedKekIv

    /**
     * First-time vault creation. Caller has authenticated via BiometricPrompt
     * and supplies an encrypt-mode Cipher initialized with the device-auth
     * Keystore key. The cipher's doFinal will succeed only if the user has
     * actually authenticated.
     *
     * Snake-eats-tail: stores the master KEK as the first vault entry so
     * the user can transcribe it for disaster recovery (biometric-gated
     * reveal, mirroring passgen).
     */
    fun createV2(
        ctx: Context,
        deviceAuthEncryptCipher: javax.crypto.Cipher,
    ): UnlockedAegisVault {
        sweepTmp(ctx)
        val masterKek = Crypto.randomBytes(MASTER_KEK_BYTES)
        try {
            val wrappedKekCt = deviceAuthEncryptCipher.doFinal(masterKek)
            val wrappedKekIv = deviceAuthEncryptCipher.iv

            // Seal the master into the vault as entry[0] for recovery.
            val masterB64 = android.util.Base64.encodeToString(
                masterKek,
                android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING,
            )
            val masterEntry = AegisEntry(
                issuer = "aegis",
                account = "vault master key",
                secretB64 = masterB64,
                // Stored as TOTP-shape but it's not really a TOTP — the
                // type is a stretch here; we keep TOTP so UI doesn't have
                // a special case. The "code" generated from this would be
                // valid TOTP for whoever holds the secret, but we never
                // intend to USE it as a TOTP — it's a recovery artifact.
                type = com.understory.security.OtpAuthEntry.Type.TOTP,
            )
            val contents = AegisVaultContents(entries = listOf(masterEntry))
            val plaintext = serialize(contents).toByteArray(Charsets.UTF_8)
            val contentCt = Crypto.aesGcmEncrypt(masterKek, plaintext)
            Crypto.wipe(plaintext)

            writeFile(ctx, wrappedKekIv, wrappedKekCt, contentCt)

            return UnlockedAegisVault(
                ctx = ctx,
                wrappedKekIv = wrappedKekIv,
                wrappedKekCt = wrappedKekCt,
                kek = masterKek.copyOf(),
                contents = contents,
            )
        } finally {
            Crypto.wipe(masterKek)
        }
    }

    /**
     * Daily unlock. Caller supplies a decrypt-mode Cipher with the stored IV,
     * authenticated via BiometricPrompt.
     */
    fun unlockV2(
        ctx: Context,
        deviceAuthDecryptCipher: javax.crypto.Cipher,
    ): UnlockedAegisVault {
        sweepTmp(ctx)
        val (header, contentCt) = readFile(ctx)
        val masterKek = deviceAuthDecryptCipher.doFinal(header.wrappedKekCt)
        try {
            val pt = Crypto.aesGcmDecrypt(masterKek, contentCt)
            val text = String(pt, Charsets.UTF_8)
            Crypto.wipe(pt)
            val contents = parse(text)
            return UnlockedAegisVault(
                ctx = ctx,
                wrappedKekIv = header.wrappedKekIv,
                wrappedKekCt = header.wrappedKekCt,
                kek = masterKek.copyOf(),
                contents = contents,
            )
        } finally {
            Crypto.wipe(masterKek)
        }
    }

    // -- file helpers ------------------------------------------------------

    private data class Header(
        val wrappedKekIv: ByteArray,
        val wrappedKekCt: ByteArray,
    )

    internal fun writeFile(
        ctx: Context,
        wrappedKekIv: ByteArray,
        wrappedKekCt: ByteArray,
        contentCt: ByteArray,
    ) {
        val tmp = File(ctx.filesDir, "$FILE.tmp")
        tmp.outputStream().use { out ->
            out.write(byteArrayOf(VERSION_V1))
            out.write(intBE(wrappedKekIv.size))
            out.write(wrappedKekIv)
            out.write(intBE(wrappedKekCt.size))
            out.write(wrappedKekCt)
            out.write(intBE(contentCt.size))
            out.write(contentCt)
        }
        atomicReplace(tmp, File(ctx.filesDir, FILE))
    }

    private fun readFile(ctx: Context): Pair<Header, ByteArray> {
        val f = File(ctx.filesDir, FILE)
        require(f.exists()) { "vault not initialised" }
        f.inputStream().use { input ->
            val v = input.read()
            require(v == VERSION_V1.toInt()) { "expected v1 vault, got version $v" }
            // Sanity caps on each length read from the file. A corrupt or
            // hostile vault file with e.g. 0xFFFFFFFF length crashes
            // ByteArray(-1) with NegativeArraySizeException; with
            // 0x7FFFFFFF it allocates ~2 GB and OOMs. Realistic upper
            // bounds: AES-GCM IV is 12-16 B, the wrapped 32-byte KEK with
            // GCM tag fits in <100 B, and the entries blob's reasonable
            // ceiling is a few MB even for thousands of TOTP entries.
            val ivLen = readIntBE(input)
            require(ivLen in 1..MAX_IV_LEN) { "vault iv length out of range: $ivLen" }
            val iv = ByteArray(ivLen); input.readFully(iv)
            val ctLen = readIntBE(input)
            require(ctLen in 1..MAX_WRAPPED_KEK_LEN) { "vault ct length out of range: $ctLen" }
            val ct = ByteArray(ctLen); input.readFully(ct)
            val contentLen = readIntBE(input)
            require(contentLen in 1..MAX_CONTENT_LEN) { "vault content length out of range: $contentLen" }
            val content = ByteArray(contentLen); input.readFully(content)
            // Reject trailing bytes after the declared payload. The bytes
            // outside the declared sections are NOT covered by AES-GCM
            // AAD (yet — see TODO around AAD framing), so silent
            // acceptance would let an attacker who can write to the
            // vault file append data the loader ignores. Hard-fail keeps
            // the file shape unambiguous.
            require(input.read() == -1) { "trailing bytes after vault content" }
            return Header(iv, ct) to content
        }
    }

    private const val MAX_IV_LEN = 256
    private const val MAX_WRAPPED_KEK_LEN = 256
    private const val MAX_CONTENT_LEN = 8 * 1024 * 1024  // 8 MiB

    private fun atomicReplace(src: File, dst: File) {
        try {
            java.nio.file.Files.move(
                src.toPath(), dst.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
            )
            return
        } catch (_: Throwable) {
            // Fall through.
        }
        if (!src.renameTo(dst)) {
            dst.delete()
            check(src.renameTo(dst)) { "vault save failed" }
        }
    }

    fun serialize(c: AegisVaultContents): String {
        val arr = JSONArray()
        for (e in c.entries) arr.put(e.toJson())
        return JSONObject().apply { put("entries", arr) }.toString()
    }

    fun parse(text: String): AegisVaultContents {
        val o = JSONObject(text)
        val arr = o.optJSONArray("entries") ?: JSONArray()
        val entries = mutableListOf<AegisEntry>()
        for (i in 0 until arr.length()) entries.add(AegisEntry.fromJson(arr.getJSONObject(i)))
        return AegisVaultContents(entries)
    }

    private fun intBE(n: Int): ByteArray = byteArrayOf(
        ((n ushr 24) and 0xFF).toByte(),
        ((n ushr 16) and 0xFF).toByte(),
        ((n ushr 8) and 0xFF).toByte(),
        (n and 0xFF).toByte(),
    )

    private fun readIntBE(input: java.io.InputStream): Int {
        val b = ByteArray(4); input.readFully(b)
        return ((b[0].toInt() and 0xFF) shl 24) or
            ((b[1].toInt() and 0xFF) shl 16) or
            ((b[2].toInt() and 0xFF) shl 8) or
            (b[3].toInt() and 0xFF)
    }

    private fun java.io.InputStream.readFully(buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = read(buf, off, buf.size - off)
            require(n >= 0) { "short read" }
            off += n
        }
    }
}

/** In-memory unlocked aegis vault. */
class UnlockedAegisVault internal constructor(
    ctx: Context,
    private val wrappedKekIv: ByteArray,
    private val wrappedKekCt: ByteArray,
    private val kek: ByteArray,
    var contents: AegisVaultContents,
) {
    // Always store the application context — never an Activity context.
    // UnlockedAegisVault lives in the AegisVaultManager process-singleton,
    // which survives across activity recreation (and is also read from the
    // IME service in a different lifecycle entirely). Holding an Activity
    // context here would leak it. Application context has the same
    // contentResolver / filesDir / etc. and is process-scoped.
    //
    // Lint's StaticFieldLeak analyzer is structural — it flags any Context
    // field reachable from a singleton — and doesn't trace the
    // applicationContext coercion. Suppression contract: a future
    // regression that drops the .applicationContext coercion must also
    // remove this comment + suppression annotation in lockstep.
    @SuppressLint("StaticFieldLeak")
    private val ctx: Context = ctx.applicationContext

    fun save() {
        val plaintext = AegisVault.serialize(contents).toByteArray(Charsets.UTF_8)
        val ct = Crypto.aesGcmEncrypt(kek, plaintext)
        Crypto.wipe(plaintext)
        AegisVault.writeFile(ctx, wrappedKekIv, wrappedKekCt, ct)
    }

    fun lock() {
        Crypto.wipe(kek)
        contents = AegisVaultContents(emptyList())
    }
}
