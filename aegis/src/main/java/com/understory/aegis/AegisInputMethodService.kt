package com.understory.aegis

import android.content.Intent
import android.graphics.Color
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
import com.understory.security.Totp

/**
 * Aegis IME — list saved TOTP entries and inject the current 6-digit code
 * directly into the focused field via [android.view.inputmethod.InputConnection.commitText].
 *
 * Two states:
 *   1. **Vault locked** (the common case at first IME activation): show
 *      a single "Open aegis to unlock first" button. Tapping it launches
 *      [MainActivity] so the user can authenticate. The IME stays open in
 *      the background; once unlocked, the user switches back to aegis IME
 *      and sees the entry list.
 *   2. **Vault unlocked** (MainActivity authed within this process and
 *      didn't lock): show the list of entries, each row tappable to inject
 *      its current code.
 *
 * Why no biometric directly in the IME: BiometricPrompt requires a
 * FragmentActivity host, and InputMethodService isn't one. We could spin
 * up a transparent FragmentActivity for the prompt, but that's a heavier
 * UX (modal pops over the user's actual app). Cleaner: do the unlock in
 * the main aegis app, then use the IME.
 *
 * Same hardening posture as passgen IME:
 *   - FLAG_SECURE on the IME window
 *   - Hard refusal on debugger / Tamper.hardFail
 *   - Plain Android Views (no Compose) to keep surface area small
 *   - importantForAutofill / contentCapture / accessibility set to NO
 *   - Tap-jacking: ObscuredTouchGate filters DOWN + MOVE on every
 *     interactive view
 *   - Crash-catcher around onCreateInputView: any exception renders a
 *     refusal view with the throwable instead of crashing the process
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
            else if (!AegisVaultManager.isUnlocked) lockedView()
            else buildEntryListView()
        } catch (t: Throwable) {
            crashView(t)
        }
    }

    override fun onStartInput(attribute: EditorInfo?, restarting: Boolean) {
        super.onStartInput(attribute, restarting)
        runCatching {
            // Force a fresh Tamper read on every input start. The IME
            // persists across many focus changes; without invalidate(),
            // a hostile install during a typing session could be absorbed
            // by the 5s cache for up to 5s.
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

    private fun lockedView(): View {
        val ctx = this
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val root = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0B0B0B"))
            setPadding(pad, pad, pad, pad)
            setImportantForContentCapture(View.IMPORTANT_FOR_CONTENT_CAPTURE_NO)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            filterTouchesWhenObscured = true
        }
        root.addView(TextView(ctx).apply {
            text = "aegis keyboard"
            setTextColor(Color.parseColor("#E0E0E0"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
        })
        root.addView(TextView(ctx).apply {
            text = "Vault is locked.\nOpen aegis once to authenticate, then switch back here."
            setTextColor(Color.parseColor("#9E9E9E"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, (8 * density).toInt(), 0, (12 * density).toInt())
        })
        root.addView(Button(ctx).apply {
            text = "Open aegis"
            isAllCaps = false
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.parseColor("#3F51B5"))
            setOnTouchListener(ObscuredTouchGate())
            setOnClickListener {
                runCatching {
                    val intent = Intent(applicationContext, MainActivity::class.java).apply {
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
        root.addView(Button(ctx).apply {
            text = "Switch back to your keyboard"
            isAllCaps = false
            setTextColor(Color.parseColor("#E0E0E0"))
            setBackgroundColor(Color.parseColor("#1E1E1E"))
            setOnClickListener { runCatching { switchToPreviousInputMethod() } }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (44 * density).toInt(),
            )
        })
        return root
    }

    private fun buildEntryListView(): View {
        val ctx = this
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val gap = (6 * density).toInt()

        val vault = AegisVaultManager.current
            ?: return lockedView()  // race: was unlocked at gate, locked by now

        val outer = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#0B0B0B"))
            setPadding(pad, pad, pad, pad)
            setImportantForContentCapture(View.IMPORTANT_FOR_CONTENT_CAPTURE_NO)
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            filterTouchesWhenObscured = true
        }
        outer.addView(TextView(ctx).apply {
            text = "aegis keyboard — tap to insert code"
            setTextColor(Color.parseColor("#E0E0E0"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setPadding(0, 0, 0, gap)
        })

        val scroll = ScrollView(ctx).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (220 * density).toInt(),
            )
        }
        val list = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
        }
        scroll.addView(list)

        val entries = vault.contents.entries
        if (entries.isEmpty()) {
            list.addView(TextView(ctx).apply {
                text = "No entries yet. Add one in the main aegis app."
                setTextColor(Color.parseColor("#9E9E9E"))
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            })
        } else {
            val nowSeconds = System.currentTimeMillis() / 1000L
            for (entry in entries) {
                val secret = entry.secretBytes()
                val code = try {
                    runCatching { Totp.currentCode(secret, nowSeconds) }
                        .getOrDefault("------")
                } finally {
                    // Wipe the decoded secret as soon as the code is
                    // computed. The IME view is held by the input-method
                    // service for as long as the keyboard stays open;
                    // without this each visible entry's secret would sit
                    // decoded in heap for the duration.
                    com.understory.security.Crypto.wipe(secret)
                }
                val secondsLeft = entry.period - (nowSeconds % entry.period).toInt()
                list.addView(buildEntryButton(entry, code, secondsLeft, density, gap))
            }
        }
        outer.addView(scroll)

        outer.addView(Button(ctx).apply {
            text = "Switch back to your keyboard"
            isAllCaps = false
            setTextColor(Color.parseColor("#E0E0E0"))
            setBackgroundColor(Color.parseColor("#1E1E1E"))
            setOnClickListener { runCatching { switchToPreviousInputMethod() } }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (44 * density).toInt(),
            )
            lp.topMargin = gap
            layoutParams = lp
        })
        return outer
    }

    private fun buildEntryButton(
        entry: AegisEntry,
        code: String,
        secondsLeft: Int,
        density: Float,
        gap: Int,
    ): View {
        val label = (entry.issuer.ifEmpty { "(no issuer)" } +
            (if (entry.account.isNotEmpty()) " — ${entry.account}" else ""))
        val formattedCode = if (code.length == 6)
            "${code.substring(0, 3)} ${code.substring(3)}"
        else code

        val btn = Button(this).apply {
            text = "$formattedCode    ($secondsLeft s)\n$label"
            isAllCaps = false
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.parseColor("#3F51B5"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            setOnTouchListener(ObscuredTouchGate())
            setOnClickListener {
                runCatching {
                    val ic = currentInputConnection ?: return@runCatching
                    // Re-check unlocked at click time. The view's `code`
                    // string was computed when the list was built; in the
                    // interval the Activity may have hit onStop and locked
                    // the vault. Without this re-check we'd inject a code
                    // for a logically-locked vault.
                    if (!AegisVaultManager.isUnlocked) return@runCatching
                    if (Tamper.check(applicationContext).hardFail) return@runCatching
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
        return btn
    }

    private fun refusalView(reason: String): View {
        val pad = (24 * resources.displayMetrics.density).toInt()
        return TextView(this).apply {
            text = "aegis ime disabled: $reason"
            setTextColor(Color.parseColor("#FFB74D"))
            setBackgroundColor(Color.parseColor("#0B0B0B"))
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
            setTextColor(Color.parseColor("#EF5350"))
            setBackgroundColor(Color.parseColor("#0B0B0B"))
            setPadding(pad, pad, pad, pad)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 10f)
        }
    }
}

/**
 * Mirrors passgen's gate: drop touches when the window is obscured (fully
 * or partially) on either DOWN or MOVE. On legitimate ACTION_UP we call
 * View.performClick so screen readers (TalkBack) hear the click event —
 * lint flags any onTouch that swallows up events without performing the
 * accessibility-aware click, which would otherwise break TalkBack
 * navigation through the IME.
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
