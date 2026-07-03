package com.understory.aegis

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import android.content.Intent
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import com.understory.security.A11yProbe
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.OtpAuthEntry
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.Tamper
import com.understory.security.TestingMode
import com.understory.security.VaultImportScreen
import com.understory.security.VaultRecovery
import com.understory.security.VaultRecoveryScreen
import com.understory.security.ui.Bg
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

/**
 * Aegis — local TOTP/HOTP authenticator. Phase A:
 *   - BiometricPrompt-gated setup + unlock (matches passgen)
 *   - List view with auto-refreshing 30s codes
 *   - Manual entry add (issuer / account / base32 secret)
 *   - Tap a code → copies to clipboard with EXTRA_IS_SENSITIVE
 *
 * Phase B will add: gallery-only QR import, IME mode, edit/delete.
 */
class MainActivity : FragmentActivity() {

    private var unlocked: UnlockedAegisVault?
        get() = AegisVaultManager.current
        set(value) {
            if (value == null) AegisVaultManager.clear()
            else AegisVaultManager.setUnlocked(value)
        }

    // Pending "Open with…" import URI, observable by the composition. Set from
    // onCreate's intent AND from onNewIntent (warm-task fix, design §6 D-S2) so
    // opening a file while the task is already alive no longer silently drops it.
    private val pendingImportUri = androidx.compose.runtime.mutableStateOf<android.net.Uri?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("aegis.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        super.onCreate(savedInstanceState)
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("aegis.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("aegis crash", color = Color(0xFFEF5350), fontSize = 18.sp)
                        Text(t.toString(), color = Color(0xFFE0E0E0), fontSize = 11.sp)
                    }
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        Diagnostics.log("aegis.MainActivity", "onPause (inFlight=${AegisVaultManager.isInTransientFlight})")
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            com.understory.security.SuiteAttestation.verify(applicationContext).hardFail
        ) {
            finishAndRemoveTask(); return
        }

        // TestingMode.ALLOW_SCREENSHOTS == true skips this so we can
        // screenshot the diagnostic surface during testing. RELEASE-BLOCKER
        // to flip back; tracked in RELEASE_BLOCKERS.md.
        if (!TestingMode.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                window.setHideOverlayWindows(true)
            }
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        // ACTION_VIEW with content URI: user picked a JSON / text export
        // and chose aegis from the system "Open with…" dialog. Pull the
        // URI here so it flows through unlock and lands in the import
        // screen with content pre-loaded — the user still has to unlock
        // with biometric and confirm explicitly. Mirrors passgen's flow.
        if (intent?.action == android.content.Intent.ACTION_VIEW) {
            pendingImportUri.value = intent?.data
        }

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
                    AegisRoot(
                        activity = this,
                        unlockedRef = ::unlocked,
                        setUnlocked = { unlocked = it },
                        onClose = { finishAndRemoveTask() },
                        pendingImportState = pendingImportUri,
                    )
                }
            }
        }

        // Note: lifted `window.decorView.filterTouchesWhenObscured = true`
        // per SAMSUNG_QUIRKS.md — the global decor filter silently drops
        // legitimate taps under Samsung Edge Panel and similar overlays.
        // Per-control SecureButton wrappers still gate the destructive
        // paths (secret reveal, delete confirms). FLAG_SECURE on the
        // window still prevents screenshot / overlay capture.
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        val inFlight = AegisVaultManager.isInTransientFlight
        Diagnostics.log("aegis.MainActivity",
            "onUserLeaveHint (inFlight=$inFlight, keepAlive=${TestingMode.KEEP_ALIVE_ON_LEAVE})")
        // Skip during a deliberate transient round-trip (QR-from-gallery
        // SAF picker, biometric prompt). On Samsung One UI the SAF
        // chooser registers as a user-leave signal — without this gate,
        // opening the QR picker would lock the vault AND finish the
        // activity before the picker can deliver a result.
        if (inFlight) return
        // Skip during the testing phase so the app stays alive in
        // memory and the user doesn't have to re-authenticate after
        // switching to chat to paste diagnostics. RELEASE-BLOCKER to
        // flip TestingMode.KEEP_ALIVE_ON_LEAVE to false before publish.
        if (TestingMode.KEEP_ALIVE_ON_LEAVE) return
        unlocked?.lock()
        unlocked = null
        finishAndRemoveTask()
    }

    /**
     * Lock on onStop, NOT onPause. onPause fires during transient
     * occlusions — system permission dialogs, biometric prompts on some
     * OEMs, and crucially the SAF gallery picker we use for QR import.
     * Locking on onPause wipes the KEK during such a round-trip; the
     * Compose AddScreen still holds a reference to the vault, and on
     * return calls vault.save() against a zero KEK, producing a
     * corrupted-on-disk vault. onStop is the well-defined "no longer
     * visible" boundary — leaving the screen, switching apps, screen-off.
     */
    override fun onStop() {
        super.onStop()
        val inFlight = AegisVaultManager.isInTransientFlight
        val isCfg = isChangingConfigurations
        val keepAlive = TestingMode.KEEP_ALIVE_ON_LEAVE
        Diagnostics.log("aegis.MainActivity",
            "onStop (inFlight=$inFlight, changingConfigs=$isCfg, keepAlive=$keepAlive, willLock=${!isCfg && !inFlight && !keepAlive})")
        DiagnosticsDump.snapshotState(this, "onStop")
        // Preserve the unlocked vault across:
        //   - deliberate transient round-trips (SAF picker, biometric prompt)
        //   - the testing phase (TestingMode.KEEP_ALIVE_ON_LEAVE — RELEASE-
        //     BLOCKER to flip false before publish; for now, switching apps
        //     and coming back doesn't force re-auth)
        if (!isCfg && !inFlight && !keepAlive) {
            unlocked?.lock()
            unlocked = null
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Diagnostics.log("aegis.MainActivity", "onDestroy")
        unlocked?.lock()
        unlocked = null
    }

    override fun onResume() {
        super.onResume()
        Diagnostics.log("aegis.MainActivity", "onResume")
        Tamper.invalidate()
        if (Tamper.check(applicationContext).hardFail) {
            Diagnostics.error("aegis.MainActivity", "Tamper.check hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }

    /**
     * Warm-task "Open with aegis" (design §6 D-S2). launchMode="singleTask"
     * means a second VIEW intent arrives here, not through onCreate, so the old
     * onCreate-only read silently dropped it. Stash the URI in the observable
     * holder and setIntent so recreation sees it too; the composition's
     * unlock-gated import path picks it up.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        Diagnostics.log("aegis.MainActivity", "onNewIntent (action=${intent.action})")
        if (intent.action == Intent.ACTION_VIEW) {
            setIntent(intent)
            pendingImportUri.value = intent.data
        }
    }
}

private enum class Stage { Setup, Unlock, Recovery, List, Add, Export, Import, Keyboard, Diagnostics }

@Composable
private fun AegisRoot(
    activity: FragmentActivity,
    unlockedRef: () -> UnlockedAegisVault?,
    setUnlocked: (UnlockedAegisVault?) -> Unit,
    onClose: () -> Unit,
    pendingImportState: androidx.compose.runtime.MutableState<android.net.Uri?>,
) {
    val ctx = LocalContext.current
    // Startup routing: an invalidated key (biometric change / lock-screen
    // change) leaves the header on disk but the wrap key gone. Route straight
    // to Recovery instead of a doomed BiometricPrompt (design §4.2).
    val initialStage = remember {
        when (VaultRecovery.keyStateAtStartup(ctx, AegisVault.exists(ctx))) {
            VaultRecovery.VaultKeyState.NEVER_CREATED -> Stage.Setup
            VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED -> Stage.Recovery
            else -> Stage.Unlock
        }
    }
    var stageName by rememberSaveable { mutableStateOf(initialStage.name) }
    val stage = remember(stageName) { Stage.valueOf(stageName) }
    val setStage: (Stage) -> Unit = {
        Diagnostics.log("aegis.Root", "stage transition: $stageName → ${it.name}")
        stageName = it.name
    }
    // Pending URI from "Open with…". Observed from the Activity-level state so
    // onNewIntent (warm task) delivers here too. Consumed once on entry to Add.
    var pendingImport by pendingImportState
    val backToList: () -> Unit = {
        pendingImport = null
        setStage(Stage.List)
    }
    // A fresh "Open with…" URI arriving while we're already on List routes into
    // the unlock-gated Add import path.
    LaunchedEffect(pendingImport, stage) {
        if (pendingImport != null && stage == Stage.List) setStage(Stage.Add)
    }
    when (stage) {
        Stage.Setup -> {
            KeepAliveBackHandler("aegis.Root.Setup")
            SetupScreen(activity = activity, onCreated = {
                setUnlocked(it)
                setStage(if (pendingImport != null) Stage.Add else Stage.List)
            }, onClose = onClose)
        }
        Stage.Unlock -> {
            KeepAliveBackHandler("aegis.Root.Unlock")
            UnlockScreen(
                activity = activity,
                onUnlocked = {
                    setUnlocked(it)
                    setStage(if (pendingImport != null) Stage.Add else Stage.List)
                },
                onClose = onClose,
                onInvalidated = { setStage(Stage.Recovery) },
            )
        }
        Stage.Recovery -> {
            KeepAliveBackHandler("aegis.Root.Recovery")
            // keyUsable=false here: the recovery screen is reached because the
            // key was destroyed, so export-first is impossible; restore-from-
            // backup or reset are the two honest paths.
            RecoveryScreen(
                onReset = {
                    setUnlocked(null)
                    setStage(Stage.Setup)
                },
                onRestore = { setStage(Stage.Import) },
                onClose = onClose,
            )
        }
        Stage.List -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            KeepAliveBackHandler("aegis.Root.List")
            ListScreen(
                vault = v,
                onAdd = { setStage(Stage.Add) },
                onExport = { setStage(Stage.Export) },
                onImport = { setStage(Stage.Import) },
                onKeyboard = { setStage(Stage.Keyboard) },
                onLock = {
                    v.lock()
                    setUnlocked(null)
                    onClose()
                },
                onDiagnostics = { setStage(Stage.Diagnostics) },
            )
        }
        Stage.Add -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToList() }
            val incoming = pendingImport
            if (incoming != null) {
                pendingImport = null
            }
            AddScreen(
                vault = v,
                onSaved = backToList,
                onCancel = backToList,
                incomingFileUri = incoming,
            )
        }
        Stage.Export -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToList() }
            var plaintext by remember { mutableStateOf(false) }
            if (plaintext) {
                AegisPlaintextExportScreen(vault = v, onDone = { plaintext = false })
            } else {
                AegisExportFlow(
                    vault = v,
                    onExportPlaintext = { plaintext = true },
                    onDone = backToList,
                )
            }
        }
        Stage.Import -> {
            // Reached from Recovery (restore-from-backup). The shared import
            // screen decrypts a .usbe under the user's recovery key. Needs an
            // unlocked vault to merge into: if the key was invalidated we must
            // reset first, so Import from Recovery routes through a fresh Setup.
            val v = unlockedRef()
            BackHandler {
                setStage(if (v != null) Stage.List else Stage.Recovery)
            }
            if (v == null) {
                // No unlockable vault (post-invalidation). Instruct: reset first.
                RestoreNeedsResetScreen(
                    onReset = {
                        setUnlocked(null)
                        setStage(Stage.Setup)
                    },
                    onBack = { setStage(Stage.Recovery) },
                )
            } else {
                VaultImportScreen(
                    port = AegisExportPort,
                    onDone = backToList,
                )
            }
        }
        Stage.Keyboard -> {
            // Requires an unlocked session so the affordance sits behind auth,
            // consistent with the rest of the list actions.
            unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToList() }
            KeyboardEnablementScreen(onBack = backToList)
        }
        Stage.Diagnostics -> {
            BackHandler { backToList() }
            DiagnosticsScreen(onBack = backToList)
        }
    }
}

private fun deviceUnsupportedReason(ctx: Context): String? {
    val km = ctx.getSystemService(KeyguardManager::class.java)
    if (km == null || !km.isDeviceSecure) {
        return "Device screen lock required.\n\nAegis binds the vault key to your device's PIN / pattern / biometric. Set up a screen lock in system Settings, then come back."
    }
    val bm = BiometricManager.from(ctx)
    val canAuth = bm.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
    )
    if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
        return "BiometricPrompt unavailable (status $canAuth). Configure a strong biometric or device credential in system Settings."
    }
    return null
}

@Composable
private fun SetupScreen(
    activity: FragmentActivity,
    onCreated: (UnlockedAegisVault) -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var step by remember { mutableStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }
    val deviceIssue = remember { deviceUnsupportedReason(ctx) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("aegis — first-time setup", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        if (deviceIssue != null) {
            Box(modifier = Modifier.fillMaxWidth().background(Color(0xFF3D2A00), RoundedCornerShape(6.dp)).padding(12.dp)) {
                Text(deviceIssue, color = Color(0xFFFFB74D), fontSize = 12.sp)
            }
            SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
            return@Column
        }
        when (step) {
            0 -> {
                Text(
                    "Aegis self-generates a 256-bit master key, self-encrypts it under a hardware-backed Keystore key, and self-binds it to this device's screen lock. The master is never displayed and never typed. To unlock the vault, you authenticate with your device biometric or PIN.",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp,
                )
                Box(modifier = Modifier.fillMaxWidth().background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp)).padding(12.dp)) {
                    Text(
                        "aegis keeps your seeds encrypted on this device only. To survive a " +
                            "lost or reset phone — or a biometric / screen-lock change, which by " +
                            "design destroys the key — export a backup after setup: an Understory " +
                            "encrypted file, or an Aegis Authenticator-compatible JSON. There's an " +
                            "Export button on the main screen.",
                        color = Color(0xFFFFB74D), fontSize = 11.sp,
                    )
                }
                SecureButton(onClick = { step = 1 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Self-generate vault")
                }
                SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
            1 -> {
                Text("Authenticate with your device to bind the vault master key.",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp)
                error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }
                LaunchedEffect(Unit) {
                    runCatching {
                        val cipher = Crypto.deviceAuthCipherForEncrypt()
                        promptAuth(activity, "Bind aegis vault to this device", cipher,
                            onSuccess = { authed ->
                                runCatching {
                                    val v = AegisVault.createV2(ctx, authed)
                                    // Gate on activity state: if BiometricPrompt
                                    // succeeded after the user backgrounded us,
                                    // don't surface an unlocked vault to in-process
                                    // peers (the IME) without UI present. Lock and
                                    // require a fresh prompt on return.
                                    if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                        onCreated(v)
                                    } else {
                                        v.lock()
                                    }
                                }.onFailure { error = "Setup failed: ${it.message}" }
                            },
                            onError = { msg -> error = "Authentication failed: $msg" },
                            onCancel = { error = "Authentication cancelled."; step = 0 },
                        )
                    }.onFailure { error = "Crypto init failed: ${it.message}" }
                }
            }
        }
    }
}

@Composable
private fun UnlockScreen(
    activity: FragmentActivity,
    onUnlocked: (UnlockedAegisVault) -> Unit,
    onClose: () -> Unit,
    onInvalidated: () -> Unit,
) {
    val ctx = LocalContext.current
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("aegis — unlock", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text("Authenticate with your device biometric or PIN.",
            color = Color(0xFF9E9E9E), fontSize = 13.sp)
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }

        SecureButton(
            onClick = {
                if (working) return@SecureButton
                working = true; error = null
                runCatching {
                    val iv = AegisVault.ivForUnlock(ctx)
                    val cipher = Crypto.deviceAuthCipherForDecrypt(iv)
                    promptAuth(activity, "Unlock aegis vault", cipher,
                        onSuccess = { authed ->
                            runCatching {
                                val v = AegisVault.unlockV2(ctx, authed)
                                // Same lifecycle gate as setup: if the user
                                // backgrounded mid-prompt, lock immediately.
                                if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                                    onUnlocked(v)
                                } else {
                                    v.lock()
                                    working = false
                                }
                            }.onFailure { t ->
                                // Route a destroyed key to Recovery, not a
                                // dead-end (design §4.2).
                                working = false
                                if (VaultRecovery.classifyUnlockFailure(t) ==
                                    VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED
                                ) onInvalidated()
                                else error = "Vault decryption failed."
                            }
                        },
                        onError = { msg ->
                            error = "Authentication failed: $msg"; working = false
                        },
                        onCancel = {
                            error = "Authentication cancelled."; working = false
                        },
                    )
                }.onFailure { t ->
                    working = false
                    if (VaultRecovery.classifyUnlockFailure(t) ==
                        VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED
                    ) onInvalidated()
                    else error = "Crypto init failed: ${t.message}"
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Authenticating…" else "Unlock with device auth")
        }
        SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
    }
}

private fun promptAuth(
    activity: FragmentActivity,
    title: String,
    cipher: Cipher,
    onSuccess: (Cipher) -> Unit,
    onError: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val executor = ContextCompat.getMainExecutor(activity)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            val c = result.cryptoObject?.cipher
            if (c == null) onError("no cipher") else onSuccess(c)
        }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            if (errorCode in setOf(
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED,
                )) onCancel() else onError(errString.toString())
        }
    }
    val prompt = BiometricPrompt(activity, executor, callback)
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle("aegis vault")
        .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        .build()
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

@Composable
private fun ListScreen(
    vault: UnlockedAegisVault,
    onAdd: () -> Unit,
    onExport: () -> Unit,
    onImport: () -> Unit,
    onKeyboard: () -> Unit,
    onLock: () -> Unit,
    onDiagnostics: () -> Unit,
) {
    val ctx = LocalContext.current

    // Tick once per second so the countdown indicator updates smoothly.
    var tickSeconds by remember { mutableStateOf(System.currentTimeMillis() / 1000L) }
    LaunchedEffect(Unit) {
        while (true) {
            tickSeconds = System.currentTimeMillis() / 1000L
            delay(1000)
        }
    }

    // Dismissible export-first nudge (design §4.2): recovery is only real if an
    // export exists, so steer the user to make one. Session-scoped dismissal.
    var nudgeDismissed by remember { mutableStateOf(false) }

    // Surface third-party accessibility services, since they can read on-
    // screen text. TOTP codes are by definition visible — if a malicious
    // a11y service is enabled, our 30s codes would leak. The banner makes
    // the threat surface explicit.
    val a11yState = remember { A11yProbe.check(ctx) }

    // Long-press on a row stages the entry for deletion. Confirmation
    // happens in an AlertDialog — accidental long-press is non-destructive.
    var deleteCandidate by remember { mutableStateOf<AegisEntry?>(null) }
    // Re-render trigger after a delete, since vault.contents is a var on
    // the unlocked vault and Compose otherwise won't observe the swap.
    var revision by remember { mutableStateOf(0) }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("aegis", color = Color(0xFFE0E0E0), fontSize = 22.sp)
                Text("${vault.contents.entries.size} entries",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp)
            }
        }
        if (a11yState.activeServiceCount > 0) {
            Box(
                modifier = Modifier.fillMaxWidth()
                    .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                    .padding(10.dp),
            ) {
                Text(
                    "⚠  ${a11yState.activeServiceCount} third-party accessibility service(s) active. " +
                        "TOTP codes are visible on screen — accessibility services can read them. " +
                        "Tap \"Review\" to open system settings.",
                    color = Color(0xFFFFB74D), fontSize = 11.sp,
                )
            }
            SecureOutlinedButton(
                onClick = { A11yProbe.openA11ySettings(ctx) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Review accessibility services")
            }
        }
        // Export-first nudge: shown until dismissed. Ties recovery to §3 export.
        if (!nudgeDismissed && vault.contents.entries.isNotEmpty()) {
            Box(
                modifier = Modifier.fillMaxWidth()
                    .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                    .padding(10.dp),
            ) {
                Text(
                    "Make a backup so a biometric change or a lost phone doesn't lose " +
                        "your codes. Tap Export.",
                    color = Color(0xFF9E9E9E), fontSize = 11.sp,
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SecureButton(onClick = onExport, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Export") }
                SecureOutlinedButton(onClick = { nudgeDismissed = true }, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Later") }
            }
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SecureButton(onClick = onAdd, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Add entry") }
            SecureOutlinedButton(onClick = onLock, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Lock") }
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SecureOutlinedButton(onClick = onExport, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Export") }
            SecureOutlinedButton(onClick = onImport, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Restore") }
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SecureOutlinedButton(onClick = onKeyboard, modifier = Modifier.weight(1f).fillMaxWidth()) { Text("Keyboard") }
        }
        if (vault.contents.entries.isEmpty()) {
            Spacer(Modifier.height(20.dp))
            Text("No entries yet. Tap \"Add entry\" to add one.",
                color = Color(0xFF9E9E9E), fontSize = 13.sp)
            Spacer(Modifier.weight(1f))
        } else {
            // revision is read so Compose treats the LazyColumn as dirty after
            // a delete swap.
            @Suppress("UNUSED_EXPRESSION") revision
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth().weight(1f),
            ) {
                items(vault.contents.entries, key = { it.id }) { entry ->
                    if (entry.type == OtpAuthEntry.Type.HOTP) {
                        HotpRow(
                            entry = entry,
                            onGenerate = {
                                runCatching {
                                    // Advance + persist BEFORE copying; propagate
                                    // on save failure (no code served on desync).
                                    val code = AegisCode.advanceHotp(vault, entry)
                                    // HOTP codes don't expire on a clock; fixed 60s
                                    // clipboard window, advertised honestly.
                                    copyCodeToClipboard(ctx, code, windowSeconds = 60)
                                    revision++
                                    val newCounter = entry.counter + 1
                                    Toast.makeText(
                                        ctx,
                                        "Code copied — counter advanced to $newCounter (60s clipboard window)",
                                        Toast.LENGTH_SHORT,
                                    ).show()
                                }.onFailure {
                                    Toast.makeText(ctx, "Generate failed: ${it.message}", Toast.LENGTH_LONG).show()
                                }
                            },
                            onLongPress = { deleteCandidate = entry },
                        )
                    } else {
                        EntryRow(
                            entry = entry,
                            nowSeconds = tickSeconds,
                            onTap = { code ->
                                // Copy window = the entry's real period, and the
                                // toast reads the SAME number (one source of truth,
                                // design §5.4). Clear at the entry's period.
                                copyCodeToClipboard(ctx, code, windowSeconds = entry.period)
                                Toast.makeText(ctx, "Code copied (${entry.period}s clipboard window)",
                                    Toast.LENGTH_SHORT).show()
                            },
                            onLongPress = { deleteCandidate = entry },
                        )
                    }
                }
            }
        }
        SecureOutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
            Text("Diagnostics")
        }
        com.understory.security.SuiteStatusFooter()
    }

    // Caution dialog: irreversible removal of a 2FA secret means losing
    // the ability to generate codes for that account. Confirm explicitly.
    //
    // Tap-jacking defense: Compose's AlertDialog renders into its OWN
    // Window (separate decor view from the Activity), so the
    // filterTouchesWhenObscured = true we set on the activity decor at
    // initialize() does NOT propagate here. We hook the dialog's window
    // explicitly via LocalView, then defense-in-depth on the click
    // handlers themselves: refuse the click if the dialog window has
    // lost focus (overlay-on-top would have stolen it).
    deleteCandidate?.let { entry ->
        AlertDialog(
            onDismissRequest = { deleteCandidate = null },
            title = { Text("Delete this 2FA entry?") },
            text = {
                val dialogView = LocalView.current
                DisposableEffect(dialogView) {
                    dialogView.filterTouchesWhenObscured = true
                    onDispose { /* dialog tears down with view; nothing to undo */ }
                }
                Column {
                    Text(
                        entry.issuer.ifEmpty { "(no issuer)" } +
                            (if (entry.account.isNotEmpty()) " — ${entry.account}" else ""),
                        color = Color(0xFFE0E0E0), fontSize = 14.sp,
                    )
                    Spacer(Modifier.height(10.dp))
                    Text(
                        "Removing this entry permanently destroys the secret in this vault. " +
                            "You won't be able to generate codes for this account again unless " +
                            "you re-enroll with the original issuer or restore from a backup.",
                        color = Color(0xFFFFB74D), fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                val dialogView = LocalView.current
                TextButton(onClick = {
                    // Defense in depth: refuse the destructive action if
                    // the dialog window has lost focus to an overlay
                    // mid-click.
                    if (!dialogView.hasWindowFocus()) return@TextButton
                    val target = entry
                    deleteCandidate = null
                    runCatching {
                        vault.contents = vault.contents.copy(
                            entries = vault.contents.entries.filter { it.id != target.id },
                        )
                        vault.save()
                        revision++
                        Toast.makeText(ctx, "Entry deleted", Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(ctx, "Delete failed: ${it.message}", Toast.LENGTH_LONG).show()
                    }
                }) {
                    Text("Delete", color = Color(0xFFEF5350))
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteCandidate = null }) {
                    Text("Cancel")
                }
            },
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun EntryRow(
    entry: AegisEntry,
    nowSeconds: Long,
    onTap: (String) -> Unit,
    onLongPress: () -> Unit,
) {
    // TOTP code, generated with the entry's OWN algorithm / digits / period
    // via AegisCode (the vendored Totp hardcodes SHA1/6/30 and would produce
    // codes the issuer rejects for non-default entries — audit A-U1/A-U2).
    // AegisCode owns the secret decode+wipe, so this row never holds the bytes.
    val code = remember(entry.id, nowSeconds / entry.period) {
        runCatching { AegisCode.totp(entry, nowSeconds) }.getOrDefault("-".repeat(entry.digits))
    }
    val secondsLeft = entry.period - (nowSeconds % entry.period).toInt()

    // Threat model: "screen is never secure even when device is" — codes are
    // NEVER rendered to screen. Tap copies the current code to the clipboard
    // (auto-clears at the period boundary); the row display stays redacted.
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(8.dp))
            .combinedClickable(
                onClick = { onTap(code) },
                onLongClick = onLongPress,
            )
            .padding(14.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(entry.issuer.ifEmpty { "(no issuer)" },
                    color = Color(0xFFE0E0E0), fontSize = 14.sp)
                if (entry.account.isNotEmpty()) {
                    Text(entry.account, color = Color(0xFF9E9E9E), fontSize = 11.sp)
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Bullets sized to the entry's digit count (6/7/8), so the row
                // layout is stable and the real code never reaches the tree.
                Text(
                    text = AegisCode.bullets(entry.digits),
                    color = Color(0xFF707070),
                    fontSize = 22.sp,
                )
                Spacer(Modifier.width(10.dp))
                CountdownRing(
                    secondsLeft = secondsLeft,
                    period = entry.period,
                )
            }
        }
    }
}

/**
 * HOTP row (design §1.4). No countdown ring, no auto-rendered code — HOTP codes
 * are counter-based, not time-based. A deliberate "Generate next code" action
 * advances + persists the counter, then copies. The code is never rendered at
 * rest.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun HotpRow(
    entry: AegisEntry,
    onGenerate: () -> Unit,
    onLongPress: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(8.dp))
            .combinedClickable(
                onClick = { /* HOTP action is the explicit button, not the row */ },
                onLongClick = onLongPress,
            )
            .padding(14.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(entry.issuer.ifEmpty { "(no issuer)" },
                    color = Color(0xFFE0E0E0), fontSize = 14.sp)
                Text(
                    (if (entry.account.isNotEmpty()) "${entry.account} · " else "") +
                        "HOTP · counter ${entry.counter}",
                    color = Color(0xFF9E9E9E), fontSize = 11.sp,
                )
            }
            SecureButton(onClick = onGenerate) { Text("Generate next code") }
        }
    }
}

/**
 * Circular countdown indicator. The ring shrinks from full → empty
 * over the TOTP period; color shifts green → amber → red as the
 * window expires. The numeric seconds-left is shown inside the ring.
 *
 * Drawn via Compose Canvas so we get clean anti-aliased arcs without
 * pulling in a chart library.
 */
@Composable
private fun CountdownRing(secondsLeft: Int, period: Int) {
    val color = colorForCountdown(secondsLeft)
    Box(
        modifier = Modifier.size(34.dp),
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.foundation.Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = 3.dp.toPx()
            val sweepFraction = secondsLeft.toFloat() / period.coerceAtLeast(1)
            // Background ring (dim).
            drawArc(
                color = Color(0xFF333333),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                style = androidx.compose.ui.graphics.drawscope.Stroke(width = stroke),
            )
            // Foreground arc, decreasing as time runs out.
            drawArc(
                color = color,
                startAngle = -90f,
                sweepAngle = 360f * sweepFraction,
                useCenter = false,
                style = androidx.compose.ui.graphics.drawscope.Stroke(
                    width = stroke,
                    cap = androidx.compose.ui.graphics.StrokeCap.Round,
                ),
            )
        }
        Text(
            "$secondsLeft",
            color = color,
            fontSize = 11.sp,
        )
    }
}

private fun colorForCountdown(seconds: Int): Color = when {
    seconds <= 5 -> Color(0xFFEF5350)
    seconds <= 10 -> Color(0xFFFFB74D)
    else -> Color(0xFF81C784)
}

/**
 * Copy a code to the system clipboard with the sensitive flag and an auto-clear
 * at [windowSeconds] — the SAME number the call site's toast advertises (one
 * source of truth, design §5.4). For TOTP pass the entry's real period; for
 * HOTP a fixed 60s. Previously this hardcoded 30s while the toast said the
 * entry's period, an honesty bug (A-M2).
 */
private fun copyCodeToClipboard(ctx: Context, code: String, windowSeconds: Int) {
    com.understory.security.Clipboard.copySensitive(
        context = ctx,
        text = code,
        autoClearSeconds = windowSeconds,
        label = "aegis-code",
    )
}

@Composable
private fun AddScreen(
    vault: UnlockedAegisVault,
    onSaved: () -> Unit,
    onCancel: () -> Unit,
    incomingFileUri: android.net.Uri? = null,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secretInput by remember { mutableStateOf("") }
    var secretRevealed by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var qrFeedback by remember { mutableStateOf<String?>(null) }
    // Loading flag covering QR decode + file import (design §5.3 — none existed).
    var working by remember { mutableStateOf(false) }

    // Gallery picker — SAF-backed, no READ_MEDIA_* permission required.
    // User picks one image at a time; we decode it in-process via ZXing.
    // Decode + parse run OFF the main thread (Bg.cpu) so a big image can't ANR;
    // the vault re-encrypt + disk write run on Bg.io. UI hops back to main.
    val qrPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        Diagnostics.log("aegis.Add",
            "qrPicker result: uri=${if (uri != null) "non-null" else "null"}")
        AegisVaultManager.endTransientFlight()
        if (uri == null) {
            qrFeedback = null
            return@rememberLauncherForActivityResult
        }
        working = true
        scope.launch {
            val decoded = withContext(Bg.cpu) { QrDecoder.decode(ctx, uri) }
            if (decoded == null) {
                qrFeedback = "Couldn't read a QR from that image. Try a clearer screenshot."
                working = false
                return@launch
            }

            // Branch on QR contents:
            //   otpauth-migration:// → Google Auth bulk export, may contain N entries
            //   otpauth://         → single-entry standard URI
            //   anything else      → treated as raw base32 secret
            if (GoogleAuthMigration.isMigrationUri(decoded)) {
                val outcome = runCatching {
                    val import = withContext(Bg.cpu) { GoogleAuthMigration.parse(decoded) }
                    if (import.entries.isEmpty()) {
                        return@runCatching "Google Auth export had no entries."
                    }
                    // Route through the shared dedup-merge (design §3.4) so the
                    // QR path dedups exactly like the file path.
                    val result = AegisMerge.merge(vault.contents.entries, import.entries)
                    import.entries.forEach { it.wipeSecret() }
                    if (result.added > 0) {
                        vault.contents = vault.contents.copy(entries = result.merged)
                        withContext(Bg.io) { vault.save() }
                    }
                    val batchNote = if (import.isMultiBatch) {
                        " (batch ${import.batchIndex + 1}/${import.batchSize} — re-run import for the remaining batches)"
                    } else ""
                    "Imported ${result.added} entries (skipped ${result.skipped} duplicates) from Google Authenticator$batchNote"
                }
                qrFeedback = outcome.getOrElse { "Couldn't parse Google Auth export: ${it.message}" }
                working = false
                return@launch
            }

            // Standard otpauth:// or raw secret path.
            secretInput = decoded
            qrFeedback = "QR decoded — secret populated. Review issuer/account and Save."
            runCatching {
                val parsed = OtpAuthEntry.parse(decoded)
                if (issuer.isBlank() && parsed.issuer.isNotEmpty()) issuer = parsed.issuer
                if (account.isBlank() && parsed.account.isNotEmpty()) account = parsed.account
                parsed.wipeSecret()
            }
            working = false
        }
    }

    // Shared file-import body. Reads via contentResolver, parses, dedups against
    // the existing vault via the shared [AegisMerge] (design §3.4), wipes parsed
    // secrets after save. All heavy work off the main thread.
    fun runFileImport(uri: android.net.Uri) {
        working = true
        scope.launch {
            val outcome = runCatching {
                val text = withContext(Bg.io) {
                    ctx.contentResolver.openInputStream(uri)?.use {
                        it.bufferedReader().readText()
                    } ?: throw IllegalStateException("Couldn't open the selected file")
                }
                val summary = withContext(Bg.cpu) { FileImports.parseAuto(text.reader()) }
                if (summary.entries.isEmpty()) {
                    val errs = if (summary.errors.isNotEmpty()) {
                        " (${summary.errorCount} parse error${if (summary.errorCount == 1) "" else "s"})"
                    } else ""
                    return@runCatching "No entries found in that file$errs."
                }
                val result = AegisMerge.merge(vault.contents.entries, summary.entries)
                summary.entries.forEach { it.wipeSecret() }
                if (result.added > 0) {
                    vault.contents = vault.contents.copy(entries = result.merged)
                    withContext(Bg.io) { vault.save() }
                }
                val errPart = if (summary.errorCount > 0) " — ${summary.errorCount} parse error${if (summary.errorCount == 1) "" else "s"} skipped" else ""
                val batchPart = summary.multiBatchHint?.let { " ($it)" } ?: ""
                "Imported ${result.added} entries (skipped ${result.skipped} duplicates)$errPart.$batchPart"
            }
            qrFeedback = outcome.getOrElse { "Import failed: ${it.message ?: it.javaClass.simpleName}" }
            working = false
        }
    }

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        Diagnostics.log("aegis.Add",
            "filePicker result: uri=${if (uri != null) "non-null" else "null"}")
        AegisVaultManager.endTransientFlight()
        if (uri == null) {
            qrFeedback = null
            return@rememberLauncherForActivityResult
        }
        runFileImport(uri)
    }

    // Auto-import path for "Open with…" → AegisRoot → AddScreen. Fires
    // once per distinct incomingFileUri value; the parent already nulls
    // the holder after first entry, so a recomposition won't replay this.
    LaunchedEffect(incomingFileUri) {
        if (incomingFileUri != null) {
            Diagnostics.log("aegis.Add", "auto-import from incoming URI")
            runFileImport(incomingFileUri)
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("add entry", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Three options:\n" +
                "  •  Pick a screenshot of a QR code from your gallery\n" +
                "  •  Paste a full otpauth:// URI directly\n" +
                "  •  Paste a base32 secret (Google Authenticator-style)\n\n" +
                "Issuer / account are optional if the QR or URI provides them.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )

        OutlinedButton(
            onClick = {
                Diagnostics.log("aegis.Add", "Pick QR screenshot: tap")
                qrFeedback = null
                AegisVaultManager.beginTransientFlight()
                runCatching { qrPicker.launch("image/*") }
                    .onFailure {
                        Diagnostics.error("aegis.Add",
                            "qrPicker.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                        AegisVaultManager.endTransientFlight()
                    }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Pick QR screenshot from gallery")
        }
        OutlinedButton(
            onClick = {
                Diagnostics.log("aegis.Add", "Import from file: tap")
                qrFeedback = null
                AegisVaultManager.beginTransientFlight()
                runCatching {
                    filePicker.launch(arrayOf(
                        "text/plain",
                        "application/json",
                        "text/csv",
                        "*/*",
                    ))
                }.onFailure {
                    Diagnostics.error("aegis.Add",
                        "filePicker.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                    AegisVaultManager.endTransientFlight()
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Import from file (otpauth-migration / Proton)")
        }
        if (working) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.material3.CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                )
                Spacer(Modifier.width(10.dp))
                Text("Working…", color = Color(0xFF9E9E9E), fontSize = 12.sp)
            }
        }
        qrFeedback?.let {
            Text(
                it,
                color = if (it.startsWith("QR decoded")) Color(0xFF81C784) else Color(0xFFFFB74D),
                fontSize = 12.sp,
            )
        }
        OutlinedTextField(
            value = issuer, onValueChange = { issuer = it },
            label = { Text("Issuer (e.g. Google)") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = account, onValueChange = { account = it },
            label = { Text("Account (e.g. you@example.com)") }, singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        // Mask the secret / otpauth:// field by default (design §5.3 D-S3) — it
        // holds the seed, and rendering it in plaintext after paste/QR decode is
        // inconsistent with redacting 30s codes everywhere else. Eye toggle to
        // reveal for verification.
        OutlinedTextField(
            value = secretInput, onValueChange = { secretInput = it },
            label = { Text("Secret or otpauth:// URI") },
            visualTransformation = if (secretRevealed) VisualTransformation.None
            else PasswordVisualTransformation(),
            trailingIcon = {
                TextButton(onClick = { secretRevealed = !secretRevealed }) {
                    Text(if (secretRevealed) "Hide" else "Show", fontSize = 12.sp)
                }
            },
            modifier = Modifier.fillMaxWidth().height(120.dp),
        )
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }
        Spacer(Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SecureButton(
                onClick = {
                    error = null
                    val parsed = try {
                        OtpAuthEntry.parse(secretInput.trim())
                    } catch (t: Throwable) {
                        error = "Couldn't parse: ${t.message ?: "invalid input"}"
                        return@SecureButton
                    }
                    val finalIssuer = issuer.trim().ifEmpty { parsed.issuer }
                    val finalAccount = account.trim().ifEmpty { parsed.account }
                    if (parsed.secret.isEmpty()) {
                        parsed.wipeSecret()
                        error = "Secret is empty."
                        return@SecureButton
                    }
                    val newEntry = AegisEntry.fromOtpAuth(parsed).copy(
                        issuer = finalIssuer,
                        account = finalAccount,
                    )
                    parsed.wipeSecret()
                    working = true
                    scope.launch {
                        val outcome = runCatching {
                            vault.contents = vault.contents.copy(
                                entries = vault.contents.entries + newEntry,
                            )
                            withContext(Bg.io) { vault.save() }
                        }
                        working = false
                        outcome.fold(
                            onSuccess = {
                                // Drop the live secret String references (Strings
                                // can't be wiped, but this frees them for GC).
                                secretInput = ""
                                issuer = ""
                                account = ""
                                onSaved()
                            },
                            onFailure = { error = "Save failed: ${it.message}" },
                        )
                    }
                },
                enabled = secretInput.isNotBlank() && !working,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) {
                Text("Save")
            }
            SecureOutlinedButton(onClick = {
                // Same secret-reference-drop on Cancel.
                secretInput = ""
                issuer = ""
                account = ""
                onCancel()
            }, modifier = Modifier.weight(1f).fillMaxWidth()) {
                Text("Cancel")
            }
        }
    }
}
