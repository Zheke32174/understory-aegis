package com.understory.aegis

import android.content.Context
import com.understory.elevation.Elevation

/**
 * OVERLAY-ATTACK SENTINEL — a READ-ONLY, FAIL-OPEN detection layer for the OTP
 * crown-jewel screens.
 *
 * The reveal/list screens are already FLAG_SECURE, which stops screenshots and
 * screen-record capture. What FLAG_SECURE does NOT stop is a hostile app drawing
 * a live overlay (TYPE_APPLICATION_OVERLAY) on top of ours — a tap-jacking /
 * phishing surface that can frame a fake prompt over a real code. When (and ONLY
 * when) an elevated shell is available, this sentinel enumerates OTHER apps that
 * currently hold an active overlay window and surfaces a warning banner naming
 * them, so the user knows the threat surface before they read a code.
 *
 * DOCTRINE (hard):
 *  - READ-ONLY. Uses only [Elevation.readShell] (`dumpsys window`, `appops`).
 *    It never takes an action; in particular it NEVER strips SYSTEM_ALERT_WINDOW
 *    itself (aegis already keeps its own overlay op stripped — this is detection,
 *    not enforcement).
 *  - FAIL-OPEN. Any null (unelevated / bind failure), parse miss, or dump-format
 *    drift degrades SILENTLY to the existing FLAG_SECURE posture: [scan] returns
 *    [Result.Inactive] and no banner is shown. We NEVER block or hide codes, and
 *    NEVER raise a false alarm, on a parse error.
 *  - OPT-IN / no dead control. When not elevated the sentinel is simply off; the
 *    caller shows no banner (FLAG_SECURE still stands). There is no greyed button
 *    here — the elevated capability is gated at the call site.
 *  - TRUST FILTER. System packages and every Understory sibling (plus aegis
 *    itself and the shared managers/launcher/settings) are excluded from the
 *    "untrusted overlay" set, so we only ever name a genuinely third-party app.
 */
object OverlaySentinel {

    /**
     * Outcome of a scan. [Inactive] is the fail-open / all-clear state — the
     * caller treats it identically to "not elevated": no banner. [Active] carries
     * the de-duplicated, trust-filtered package names of apps holding a live
     * untrusted overlay; only this state paints a banner.
     */
    sealed interface Result {
        /** No untrusted overlay detected, OR not elevated, OR any parse miss (fail-open). */
        data object Inactive : Result

        /** One or more untrusted apps hold a live overlay window right now. */
        data class Active(val packages: List<String>) : Result
    }

    // Package prefixes we treat as system / first-party and therefore NEVER name
    // as an untrusted overlay. Prefix match keeps OEM sub-packages covered.
    private val SYSTEM_PREFIXES = listOf(
        "com.google.android.",
        "com.android.",
        "android.",
        "com.samsung.android.",
        "com.sec.android.",
        "com.qualcomm.",
        "com.mediatek.",
    )

    // Exact packages that are load-bearing and must be hard-excluded from any
    // "untrusted" verdict: the launcher/settings, the VPN slot holder (Tailscale),
    // the Shizuku/Sui managers, and every Understory sibling. Aegis itself is
    // excluded too (own overlay, if any, is not a foreign threat).
    private val TRUSTED_EXACT = setOf(
        "com.understory.aegis",
        "com.tailscale.ipn",
        "moe.shizuku.privileged.api",   // Shizuku manager
        "moe.shizuku.redirect",
        "com.android.settings",
        "com.android.systemui",         // status-bar / heads-up chrome, not a foreign app
    )

    // Understory suite siblings are all first-party; any com.understory.* is trusted.
    private const val SUITE_PREFIX = "com.understory."

    /**
     * Scan for live untrusted overlays. Returns [Result.Inactive] whenever the
     * shell is unavailable or the dump can't be parsed — the caller must treat
     * Inactive as "nothing to warn about" and rely on FLAG_SECURE.
     *
     * Never throws. Runs read-only shell reads via [Elevation.readShell]; those
     * already return null on any error, and we degrade on null at every step.
     */
    suspend fun scan(ctx: Context): Result {
        // Not elevated → sentinel off. FLAG_SECURE still protects the screen.
        if (!Elevation.canRunShell(ctx)) return Result.Inactive

        return runCatching {
            val own = ctx.packageName

            // Primary signal: apps with a live TYPE_APPLICATION_OVERLAY window in
            // the window manager dump. This reflects overlays actually on screen
            // NOW, not merely apps that *could* draw one.
            val fromWindows = parseOverlayWindows(
                Elevation.readShell(ctx, listOf("dumpsys", "window", "windows")),
            )

            // Corroborating signal: apps whose SYSTEM_ALERT_WINDOW appop is
            // currently in the allow/foreground state. This catches an overlay app
            // the window dump labelled with a format we didn't recognise. It is a
            // "holds the permission" signal, so we intersect-by-union but keep the
            // trust filter strict; on any miss it contributes nothing (fail-open).
            val fromAppops = parseSawAppops(
                Elevation.readShell(ctx, listOf("appops", "query-op", "SYSTEM_ALERT_WINDOW", "allow")),
            )

            val candidates = (fromWindows + fromAppops)
                .asSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .filter { isValidPackageToken(it) }
                .filter { it != own }
                .filter { isUntrusted(it) }
                .distinct()
                .sorted()
                .toList()

            if (candidates.isEmpty()) Result.Inactive else Result.Active(candidates)
        }.getOrDefault(Result.Inactive) // fail-open on ANY throwable
    }

    // ---- parsers (defensive; every one degrades to emptySet on a miss) -------

    /**
     * Pull package names off `dumpsys window windows`. Window entries look like:
     *   Window #7 Window{... u0 pkg.name/pkg.name.Overlay}:
     *     mOwnerUid=10234 ...
     *     ty=APPLICATION_OVERLAY  (older builds: type=2038)
     * We collect the package token from a window header, but only KEEP it when the
     * same entry block advertises an application-overlay type. Being liberal about
     * the exact token spelling and strict about the type keeps false positives
     * (naming a benign app) from ever firing on a format we half-recognise.
     */
    internal fun parseOverlayWindows(dump: String?): Set<String> {
        if (dump.isNullOrBlank()) return emptySet()
        return runCatching {
            val out = LinkedHashSet<String>()
            var pendingPkg: String? = null
            for (raw in dump.lineSequence()) {
                val line = raw.trim()
                val header = WINDOW_HEADER.find(line)
                if (header != null) {
                    // New window block starts; reset the pending package.
                    pendingPkg = header.groupValues[1].substringBefore('/').takeIf { it.isNotBlank() }
                    continue
                }
                if (pendingPkg != null && isOverlayTypeLine(line)) {
                    out.add(pendingPkg!!)
                    pendingPkg = null
                }
            }
            out
        }.getOrDefault(emptySet())
    }

    /**
     * Parse `appops query-op SYSTEM_ALERT_WINDOW allow` output, which is a plain
     * newline-separated list of package names of apps currently granted the
     * overlay op. Some builds emit nothing / an error banner — both parse to empty
     * (fail-open).
     */
    internal fun parseSawAppops(dump: String?): Set<String> {
        if (dump.isNullOrBlank()) return emptySet()
        return runCatching {
            dump.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .filter { isValidPackageToken(it) }
                .toCollection(LinkedHashSet())
        }.getOrDefault(emptySet())
    }

    // ---- trust filter --------------------------------------------------------

    /** True when [pkg] is NOT system and NOT a first-party / load-bearing app. */
    private fun isUntrusted(pkg: String): Boolean {
        if (pkg in TRUSTED_EXACT) return false
        if (pkg.startsWith(SUITE_PREFIX)) return false
        if (SYSTEM_PREFIXES.any { pkg.startsWith(it) }) return false
        return true
    }

    // ---- token / format helpers ---------------------------------------------

    private fun isOverlayTypeLine(line: String): Boolean {
        // Match the type field in either the symbolic or numeric spelling.
        // 2038 = TYPE_APPLICATION_OVERLAY. Guard with word-ish boundaries so
        // "12038" or a substring never trips it.
        if (line.contains("APPLICATION_OVERLAY")) return true
        val ty = TYPE_FIELD.find(line) ?: return false
        return ty.groupValues[1] == "2038"
    }

    /**
     * A conservative package-name shape check: at least one dot, only characters
     * legal in an Android package id. Rejects dump noise (hex uids, addresses,
     * "windows", etc.) so we never name a non-package token as an overlay app.
     */
    private fun isValidPackageToken(s: String): Boolean {
        if (!s.contains('.')) return false
        if (s.length < 3 || s.length > 255) return false
        return s.all { it.isLetterOrDigit() || it == '.' || it == '_' }
    }

    // Window header: "Window{hash uN pkg/comp}" — capture the pkg/comp token.
    private val WINDOW_HEADER = Regex("""Window\{[^}]*\su\d+\s+([A-Za-z0-9._/]+)[^}]*}""")

    // "ty=2038" or "type=2038" or "ty= APPLICATION_OVERLAY" — capture the value token.
    private val TYPE_FIELD = Regex("""\bty(?:pe)?=\s*(\w+)""")
}
