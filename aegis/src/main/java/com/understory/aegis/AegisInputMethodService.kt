package com.understory.aegis

import android.content.Intent
import android.inputmethodservice.InputMethodService
import android.os.Debug
import android.util.TypedValue
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.understory.security.Tamper

/**
 * Aegis IME — list saved OTP entries and inject the current code directly into
 * the focused field via [android.view.inputmethod.InputConnection.commitText].
 *
 * Post-redesign (design §2): the IME reads the SCOPED, time-boxed
 * [AegisVaultManager.imeSession] — NOT [AegisVaultManager.current]. The old
 * design was dead: MainActivity locks the app session whenever aegis loses
 * focus (exactly when the IME is used), so `current` was always null here. Now
 * the locked view launches [AuthTrampolineActivity], which mints a separate
 * 90-second IME session and returns focus to the target app, without weakening
 * MainActivity's lock-on-leave.
 *
 * Two states:
 *   1. **No / expired IME session**: an "Unlock for keyboard" button that
 *      launches the trampoline. The keyboard stays here; on return the list
 *      renders.
 *   2. **In-TTL IME session**: the entry list. Each row's code is computed AT
 *      CLICK TIME (never captured at build time — that was the stale-code bug),
 *      honoring the entry's algorithm/digits/period (TOTP) or advancing +
 *      persisting the counter (HOTP).
 *
 * Same hardening posture as before: FLAG_SECURE, hard-refuse on debugger/tamper,
 * plain Views, a11y/autofill/contentCapture set to NO, tap-jack gate.
 */
class AegisInputMethodService : InputMethodService() {

    private var hardRefuse: String? = null

    override fun onCreate() {
        super.onCreate()
        runCatching {
            hardRefuse = when {
                Debug.isDebuggerConnected() || Debug.waitingForDebugger() ->
                    "debugger detected"
                packageName != "com.understory.aegis" ->
                    "package mismatch"
                Tamper.check(applicationContext).hardFail ->
                    "tamper detected"
                else -> null
            }
        }.onFailure { hardRefuse = "init error: ${it.javaClass.simpleName}" }
    }

    override fun onCreateInputView(): View {
        return try {
            runCatching {
                window?.window?.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE,
                )
            }
            val refusal = hardRefuse
            if (refusal != null) refusalView(refusal)
            else if (AegisVaultManager.imeSession == null) lockedView()
            else buildEntryListView()
        } catch (t: Throwable) {
            crashView(t)
        }
    }

    override fun onStartInput(attribute: EditorInfo?, restarting: Boolean) {
        super.onStartInput(attribute, restarting)
        runCatching {
            Tamper.invalidate()
            hardRefuse = when {
                Debug.isDebuggerConnected() || Debug.waitingForDebugger() ->
                    "debugger detected"
                Tamper.check(applicationContext).hardFail ->
                    "tamper detected"
                else -> null
            }
        }
    }

    private fun applyAntiScrape(v: LinearLayout) {
        // Anti-scrape posture: the IME is deliberately NOT TalkBack-navigable
        // (documented honestly on the enablement screen). Screen-reader users
        // use tap-to-copy in the app instead.
        v.setImportantForContentCapture(View.IMPORTANT_FOR_CONTENT_CAPTURE_NO)
        v.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        v.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
        v.filterTouchesWhenObscured = true
    }

    private fun lockedView(): View {
        val ctx = this
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val root = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(ImeColors.surface)
            setPadding(pad, pad, pad, pad)
        }
        applyAntiScrape(root)
        root.addView(TextView(ctx).apply {
            text = "aegis keyboard"
            setTextColor(ImeColors.onSurface)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
        })
        root.addView(TextView(ctx).apply {
            text = "Vault locked. Tap Unlock to authenticate — the keyboard stays here."
            setTextColor(ImeColors.onSurfaceVariant)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, (8 * density).toInt(), 0, (12 * density).toInt())
        })
        root.addView(Button(ctx).apply {
            text = "Unlock for keyboard"
            isAllCaps = false
            setTextColor(ImeColors.onPrimary)
            setBackgroundColor(ImeColors.primary)
            setOnTouchListener(ObscuredTouchGate())
            setOnClickListener {
                runCatching {
                    val intent = Intent(applicationContext, AuthTrampolineActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }
                    startActivity(intent)
                }
            }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (52 * density).toInt(),
            )
            lp.bottomMargin = (10 * density).toInt()
            layoutParams = lp
        })
        root.addView(switchBackButton(density, topMargin = 0))
        return root
    }

    private fun buildEntryListView(): View {
        val ctx = this
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val gap = (6 * density).toInt()

        val vault = AegisVaultManager.imeSession
            ?: return lockedView()  // race: expired between the gate and here

        val outer = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(ImeColors.surface)
            setPadding(pad, pad, pad, pad)
        }
        applyAntiScrape(outer)

        val remainingS = (AegisVaultManager.imeSessionRemainingMs / 1000L).coerceAtLeast(0L)
        outer.addView(TextView(ctx).apply {
            text = "aegis keyboard — tap to insert code  (unlocked, ${remainingS}s left)"
            setTextColor(ImeColors.onSurface)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setPadding(0, 0, 0, gap)
        })

        val scroll = ScrollView(ctx).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (220 * density).toInt(),
            )
        }
        val list = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(list)

        val entries = vault.contents.entries
        if (entries.isEmpty()) {
            list.addView(TextView(ctx).apply {
                text = "No entries yet. Add one in the main aegis app."
                setTextColor(ImeColors.onSurfaceVariant)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            })
        } else {
            for (entry in entries) list.addView(buildEntryButton(entry, density, gap))
        }
        outer.addView(scroll)
        outer.addView(switchBackButton(density, topMargin = gap))
        return outer
    }

    private fun buildEntryButton(entry: AegisEntry, density: Float, gap: Int): View {
        val label = (entry.issuer.ifEmpty { "(no issuer)" } +
            (if (entry.account.isNotEmpty()) " — ${entry.account}" else ""))
        // Masked placeholder + issuer/account only. The real code is computed at
        // CLICK time, never captured here (kills the stale build-time code bug).
        val kindHint = if (entry.type == com.understory.security.OtpAuthEntry.Type.HOTP)
            "Insert next code (HOTP)" else "Insert code"

        return Button(this).apply {
            text = "${AegisCode.bullets(entry.digits)}    $kindHint\n$label"
            isAllCaps = false
            setTextColor(ImeColors.onPrimary)
            setBackgroundColor(ImeColors.primary)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setOnTouchListener(ObscuredTouchGate())
            setOnClickListener {
                runCatching {
                    val ic = currentInputConnection ?: return@runCatching
                    // Re-read the IME session at click time — it may have expired.
                    val v = AegisVaultManager.imeSession ?: return@runCatching
                    if (Tamper.check(applicationContext).hardFail) return@runCatching
                    // Re-resolve the entry against the live session (HOTP advance
                    // mutates it) by id.
                    val live = v.contents.entries.firstOrNull { it.id == entry.id }
                        ?: return@runCatching
                    val code = if (live.type == com.understory.security.OtpAuthEntry.Type.HOTP) {
                        // Persist counter+1 BEFORE committing (same ordering as
                        // the app path). If save throws, no code is committed.
                        AegisCode.advanceHotp(v, live)
                    } else {
                        AegisCode.totp(live, System.currentTimeMillis() / 1000L)
                    }
                    ic.commitText(code, 1)
                    runCatching { switchToPreviousInputMethod() }
                }
            }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
            lp.bottomMargin = gap
            layoutParams = lp
        }
    }

    private fun switchBackButton(density: Float, topMargin: Int): Button =
        Button(this).apply {
            text = "Switch back to your keyboard"
            isAllCaps = false
            setTextColor(ImeColors.onSurface)
            setBackgroundColor(ImeColors.surfaceVariant)
            setOnClickListener { runCatching { switchToPreviousInputMethod() } }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (44 * density).toInt(),
            )
            lp.topMargin = topMargin
            layoutParams = lp
        }

    private fun refusalView(reason: String): View {
        val pad = (24 * resources.displayMetrics.density).toInt()
        return TextView(this).apply {
            text = "aegis ime disabled: $reason"
            setTextColor(ImeColors.warn)
            setBackgroundColor(ImeColors.surface)
            setPadding(pad, pad, pad, pad)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
        }
    }

    private fun crashView(t: Throwable): View {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val sw = java.io.StringWriter()
        t.printStackTrace(java.io.PrintWriter(sw))
        return TextView(this).apply {
            text = "aegis ime crash: ${t.javaClass.simpleName}: ${t.message}\n\n${sw.toString().take(2000)}"
            setTextColor(ImeColors.error)
            setBackgroundColor(ImeColors.surface)
            setPadding(pad, pad, pad, pad)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
        }
    }
}

/**
 * Drop touches when the window is obscured on DOWN or MOVE. On legitimate UP we
 * call [View.performClick] so lint's accessibility check is satisfied; the IME
 * itself is intentionally not TalkBack-navigable (documented on the enablement
 * screen), but performClick keeps the touch pipeline honest.
 */
private class ObscuredTouchGate : View.OnTouchListener {
    override fun onTouch(v: View, ev: MotionEvent): Boolean {
        when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE -> {
                val mask = MotionEvent.FLAG_WINDOW_IS_OBSCURED or
                    MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
                if ((ev.flags and mask) != 0) return true
            }
            MotionEvent.ACTION_UP -> v.performClick()
        }
        return false
    }
}
