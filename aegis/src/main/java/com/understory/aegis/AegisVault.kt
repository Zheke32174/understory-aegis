package com.understory.aegis

import android.annotation.SuppressLint
import android.content.Context
import com.understory.backup.RecoveryFile
import com.understory.backup.RecoveryWrapKey
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
 * Recovery (design §4): the vault does NOT seal its master KEK as a fake
 * entry[0]. That artifact had zero recovery value (aegis has no reveal path,
 * the "code" it produced was a meaningless TOTP-of-the-KEK) and was a hazard
 * (deletable, IME-listed, off-by-one entry count). Real recovery is the shared
 * [com.understory.security.VaultRecovery] contract: a user-held encrypted
 * export made via the Export sheet, restorable after a biometric change or a
 * lost phone. Legacy vaults that still carry the stray entry[0] self-heal on
 * unlock (see [MASTER_KEK_LEGACY_ISSUER]/[MASTER_KEK_LEGACY_ACCOUNT] and
 * [parse]).
 */
object AegisVault {

    private const val FILE = "aegis-vault.bin"
    private const val VERSION_V1: Byte = 1

    /** 32-byte symmetric KEK — same size as passgen. */
    private const val MASTER_KEK_BYTES = 32

    /**
     * Marker of the legacy fake master-KEK entry that old [createV2] builds
     * sealed as entry[0]. Any entry with this exact (issuer, account) is a
     * recovery artifact from before design §4.3 — never a usable TOTP — and is
     * dropped on load ([parse]) so existing installs self-heal without user
     * action and the entry count becomes honest.
     */
    const val MASTER_KEK_LEGACY_ISSUER = "aegis"
    const val MASTER_KEK_LEGACY_ACCOUNT = "vault master key"

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
        // Self-sealing recovery (design §4, operator directive 2026-07-03): a
        // full wipe must also drop the in-vault sealed recovery kit and its
        // non-auth wrap key, or a reset would leave a kit that unwraps to the
        // KEK of a vault that no longer exists.
        runCatching { File(ctx.filesDir, RecoveryFile.KIT_FILE).delete() }
        RecoveryWrapKey.deleteKey()
    }

    /** Read the IV needed to construct the unlock cipher. */
    fun ivForUnlock(ctx: Context): ByteArray = readFile(ctx).first.wrappedKekIv

    /**
     * First-time vault creation. Caller has authenticated via BiometricPrompt
     * and supplies an encrypt-mode Cipher initialized with the device-auth
     * Keystore key. The cipher's doFinal will succeed only if the user has
     * actually authenticated.
     *
     * The vault starts EMPTY (design §4.3). The master KEK is recoverable
     * operationally via the Keystore wrap (daily unlock) and, for disaster
     * recovery, via a user-held encrypted export (Export sheet, §3) — it is
     * never sealed into the vault as a self-copy, which added only risk.
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

            val contents = AegisVaultContents(entries = emptyList())
            val plaintext = serialize(contents).toByteArray(Charsets.UTF_8)
            val contentCt = Crypto.aesGcmEncrypt(masterKek, plaintext)
            Crypto.wipe(plaintext)

            writeFile(ctx, wrappedKekIv, wrappedKekCt, contentCt)

            // SELF-SEAL (operator directive 2026-07-03 — "the screen is the
            // enemy"). Mint a random recovery key and seal the vault's KEK to an
            // encrypted at-rest kit under the non-auth [RecoveryWrapKey]. Nothing
            // is prompted and nothing is shown; the user never sees or types the
            // recovery key. Because the wrap key survives biometric re-enrollment,
            // a fingerprint / lock-screen change can later be recovered SILENTLY
            // from this kit ([RecoveryFile.readKekFromSealedKit]).
            RecoveryFile.seal(ctx, APP_ID, masterKek)

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

    /** App id recorded in the sealed recovery kit; matches the package id. */
    private const val APP_ID = "com.understory.aegis"

    /**
     * Rebuild the vault from recovered KEK material after the device-auth key was
     * destroyed (biometric / lock-screen change) or when restoring on a fresh
     * device from an exported recovery file. The caller has authenticated via
     * BiometricPrompt and supplies an encrypt-mode Cipher initialised with a FRESH
     * device-auth Keystore key; [recoveredKek] is the vault's original KEK, which
     * still decrypts the on-disk content ciphertext.
     *
     * This re-wraps the SAME KEK under the new device-auth key and rewrites the
     * header, so all existing entries stay readable — the content ciphertext is
     * left untouched and only the wrapped-KEK header is replaced. The at-rest
     * recovery kit is re-sealed with a fresh recovery key so it tracks the new
     * bind. [recoveredKek] is COPIED internally; the caller still owns and must
     * wipe its own array.
     */
    fun rebindWithKek(
        ctx: Context,
        recoveredKek: ByteArray,
        deviceAuthEncryptCipher: javax.crypto.Cipher,
    ): UnlockedAegisVault {
        sweepTmp(ctx)
        require(recoveredKek.size == MASTER_KEK_BYTES) { "unexpected KEK size" }
        val kek = recoveredKek.copyOf()
        try {
            // Read the existing content ciphertext (still encrypted under this
            // KEK) and confirm the KEK actually decrypts it before we overwrite
            // the header — a wrong file would otherwise brick the vault.
            val existingContentCt = readFile(ctx).second
            val pt = Crypto.aesGcmDecrypt(kek, existingContentCt)
            val contents = parse(String(pt, Charsets.UTF_8))
            Crypto.wipe(pt)

            val wrappedKekCt = deviceAuthEncryptCipher.doFinal(kek)
            val wrappedKekIv = deviceAuthEncryptCipher.iv
            writeFile(ctx, wrappedKekIv, wrappedKekCt, existingContentCt)

            // Re-seal the at-rest kit so it tracks the newly-bound vault.
            RecoveryFile.reseal(ctx, APP_ID, kek)

            return UnlockedAegisVault(
                ctx = ctx,
                wrappedKekIv = wrappedKekIv,
                wrappedKekCt = wrappedKekCt,
                kek = kek.copyOf(),
                contents = contents,
            )
        } finally {
            Crypto.wipe(kek)
        }
    }

    /**
     * First-time creation on a fresh device from an imported recovery file, when
     * NO vault file exists yet. Builds a brand-new vault whose KEK is the imported
     * [recoveredKek] (so a later export/kit stays consistent) and whose contents
     * start empty — the caller then merges the restored entries via the normal
     * import path, or the exported file carried only the KEK. Mirrors [createV2]
     * but adopts the supplied KEK instead of minting one.
     */
    fun createWithKek(
        ctx: Context,
        recoveredKek: ByteArray,
        deviceAuthEncryptCipher: javax.crypto.Cipher,
    ): UnlockedAegisVault {
        sweepTmp(ctx)
        require(recoveredKek.size == MASTER_KEK_BYTES) { "unexpected KEK size" }
        val kek = recoveredKek.copyOf()
        try {
            val wrappedKekCt = deviceAuthEncryptCipher.doFinal(kek)
            val wrappedKekIv = deviceAuthEncryptCipher.iv

            val contents = AegisVaultContents(entries = emptyList())
            val plaintext = serialize(contents).toByteArray(Charsets.UTF_8)
            val contentCt = Crypto.aesGcmEncrypt(kek, plaintext)
            Crypto.wipe(plaintext)

            writeFile(ctx, wrappedKekIv, wrappedKekCt, contentCt)
            RecoveryFile.reseal(ctx, APP_ID, kek)

            return UnlockedAegisVault(
                ctx = ctx,
                wrappedKekIv = wrappedKekIv,
                wrappedKekCt = wrappedKekCt,
                kek = kek.copyOf(),
                contents = contents,
            )
        } finally {
            Crypto.wipe(kek)
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
        for (i in 0 until arr.length()) {
            val e = AegisEntry.fromJson(arr.getJSONObject(i))
            // Self-heal legacy vaults: silently drop the old fake master-KEK
            // entry[0] (design §4.3). It was never a usable TOTP, so nothing a
            // user can use is lost, and the count/first-run become honest.
            if (e.issuer == MASTER_KEK_LEGACY_ISSUER && e.account == MASTER_KEK_LEGACY_ACCOUNT) continue
            entries.add(e)
        }
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

    /**
     * A COPY of the vault's master KEK, for the self-sealing recovery file
     * ([RecoveryFile.exportKit] / [RecoveryFile.seal]). The recovery kit protects
     * the KEK material — the same bytes the old recovery-bundle path used — so an
     * exported file can rebuild the vault. The returned array is the CALLER's to
     * use and wipe; the vault keeps its own live buffer.
     */
    internal fun kekMaterial(): ByteArray = kek.copyOf()

    fun lock() {
        Crypto.wipe(kek)
        contents = AegisVaultContents(emptyList())
    }
}
