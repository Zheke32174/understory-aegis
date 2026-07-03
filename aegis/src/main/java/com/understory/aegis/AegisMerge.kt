package com.understory.aegis

import com.understory.security.OtpAuthEntry

/**
 * One dedup-merge for all three ingest paths (design §3.4): file import, the
 * Google-migration QR bulk add, and [AegisBackupAdapter.import]. Before this,
 * the QR path had no dedup at all while the file path did — the same import via
 * two doorways produced different results.
 *
 * The dedup key is `(issuer, account, secretB64)` — the audit's stated key.
 * Including the secret means two genuinely-different secrets for the same
 * (issuer, account) both survive (re-enrollment case), while an exact re-import
 * is skipped. Anonymous entries (empty issuer AND account) are compared by
 * secret alone, so re-importing the same anonymous secret still dedups.
 */
object AegisMerge {

    data class MergeResult(
        val merged: List<AegisEntry>,
        val added: Int,
        val skipped: Int,
    )

    private fun key(issuer: String, account: String, secretB64: String): Triple<String, String, String> =
        Triple(issuer.lowercase(), account.lowercase(), secretB64)

    /**
     * Merge [incoming] into [existing], skipping duplicates by the composite
     * key. Secrets inside [incoming] are NOT wiped here — the caller owns their
     * lifecycle (it typically wipes each `OtpAuthEntry` after building the
     * `AegisEntry`).
     */
    fun merge(existing: List<AegisEntry>, incoming: List<OtpAuthEntry>): MergeResult {
        val seen = HashSet<Triple<String, String, String>>()
        for (e in existing) seen += key(e.issuer, e.account, e.secretB64)

        val out = ArrayList(existing)
        var added = 0
        var skipped = 0
        for (otp in incoming) {
            val newEntry = AegisEntry.fromOtpAuth(otp)
            val k = key(newEntry.issuer, newEntry.account, newEntry.secretB64)
            if (k in seen) {
                skipped++
            } else {
                seen += k
                out += newEntry
                added++
            }
        }
        return MergeResult(out, added, skipped)
    }

    /**
     * Merge already-materialized [AegisEntry] values (the adapter path, where
     * incoming has been parsed from our own JSON). Same key/semantics.
     */
    fun mergeEntries(existing: List<AegisEntry>, incoming: List<AegisEntry>): MergeResult {
        val seen = HashSet<Triple<String, String, String>>()
        for (e in existing) seen += key(e.issuer, e.account, e.secretB64)

        val out = ArrayList(existing)
        var added = 0
        var skipped = 0
        for (e in incoming) {
            val k = key(e.issuer, e.account, e.secretB64)
            if (k in seen) {
                skipped++
            } else {
                seen += k
                out += e
                added++
            }
        }
        return MergeResult(out, added, skipped)
    }
}
