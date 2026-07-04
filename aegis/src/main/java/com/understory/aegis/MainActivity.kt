package com.understory.aegis

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Debug
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
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.CloudDownload
import androidx.compose.material.icons.outlined.CloudUpload
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import android.content.Intent
import com.understory.backup.RecoveryFile
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
import com.understory.security.secureClickable
import com.understory.security.VaultRecovery
import com.understory.security.ui.Bg
import com.understory.security.ui.components.EmptyState
import com.understory.security.ui.components.FatalScreen
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

/**
 * Aegis (store name "Understory OTP") — local TOTP/HOTP authenticator:
 *   - BiometricPrompt-gated setup + unlock
 *   - List view with auto-refreshing codes (parameter-correct via AegisCode)
 *   - Manual entry add + QR / file import
 *   - Tap a TOTP code → copies to clipboard with EXTRA_IS_SENSITIVE; HOTP has a
 *     deliberate "Generate next code" advance
 *   - Invalidated-key recovery, reachable export, and a scoped-unlock IME
 *
 * Wave-3 GUI pass: every screen is wrapped in [UnderstoryTheme] and built from
 * the shared token roles + components; user-facing copy is in strings.xml.
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

    // Set when initialize() refused to run (tamper/attestation hard-fail). Drives
    // an honest FatalScreen instead of a bare finishAndRemoveTask() vanish (CD-4c).
    private val fatalReason = androidx.compose.runtime.mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        Diagnostics.log("aegis.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        super.onCreate(savedInstanceState)
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("aegis.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
                    FatalScreen(
                        title = stringResource(R.string.fatal_start_title),
                        reason = stringResource(R.string.fatal_start_reason),
                        details = t.toString(),
                    )
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
            // CD-4c: don't vanish silently. Tell the user why the app refused to
            // continue, then let them dismiss it (which finishes the task).
            Diagnostics.error("aegis.MainActivity", "integrity hard-fail — refusing to run")
            fatalReason.value = when {
                debuggerAttached -> "A debugger is attached."
                else -> "The app failed its integrity / signature check on this device."
            }
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
        // and chose Understory OTP from the system "Open with…" dialog. Pull
        // the URI here so it flows through unlock and lands in the import
        // screen with content pre-loaded — the user still has to unlock with
        // biometric before anything is read. Mirrors passgen's flow.
        if (intent?.action == android.content.Intent.ACTION_VIEW) {
            pendingImportUri.value = intent?.data
        }

        setContent {
            UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
                val fatal = fatalReason.value
                if (fatal != null) {
                    FatalScreen(
                        title = stringResource(R.string.fatal_start_title),
                        reason = fatal,
                    )
                } else {
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
            Diagnostics.error("aegis.MainActivity", "Tamper.check hardFail on resume — surfacing fatal")
            unlocked?.lock()
            unlocked = null
            fatalReason.value = "The app failed its integrity check while running."
        }
    }

    /**
     * Warm-task "Open with…" (design §6 D-S2). launchMode="singleTask" means a
     * second VIEW intent arrives here, not through onCreate, so the old
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

private enum class Stage { Setup, Unlock, Recovery, RestoreRecovery, List, Add, Export, Keyboard, Diagnostics }

/**
 * The shared [SuiteStatusFooter] is a suite-wiring smoke test (tier / peer /
 * capability status) — genuinely useful in engineering builds, but it reads as a
 * dev/debug status strip in a shipping authenticator. Gate it to the eng flavor
 * so the prod chrome shows a clean shipping face with no status dump. The main
 * (List) screen already uses a custom bottom bar (the NavigationBar), so this
 * only affects the auxiliary SuiteScaffold screens (setup / unlock / add).
 */
private val SHOW_SUITE_FOOTER: Boolean = BuildConfig.FLAVOR == "eng"

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
            // Self-sealing recovery (operator directive 2026-07-03). The key was
            // destroyed by a biometric / lock-screen change. FIRST try a SILENT
            // in-vault re-bind from the at-rest sealed kit — no user action,
            // nothing on screen. Only if that kit is gone do we show the
            // (typing-free) "Restore from your recovery file" landing.
            var silentTried by rememberSaveable { mutableStateOf(false) }
            LaunchedEffect(silentTried) {
                if (silentTried) return@LaunchedEffect
                silentTried = true
                // readKekFromSealedKit returns null when the kit is absent or
                // undecryptable; only proceed to the biometric rebind when we
                // actually recovered the KEK. On any failure we fall through to
                // the (typing-free) "Restore from your recovery file" landing
                // already rendered below.
                val kek = withContext(Bg.io) { RecoveryFile.readKekFromSealedKit(ctx) }
                if (kek != null) {
                    rebindVaultFromKek(
                        activity = activity,
                        ctx = ctx,
                        recoveredKek = kek, // ownership transferred; wiped inside
                        onRebound = { v ->
                            setUnlocked(v)
                            setStage(if (pendingImport != null) Stage.Add else Stage.List)
                        },
                        onError = { msg -> Toast.makeText(ctx, msg, Toast.LENGTH_LONG).show() },
                    )
                }
            }
            RecoveryScreen(
                onReset = {
                    setUnlocked(null)
                    setStage(Stage.Setup)
                },
                onRestoreFromFile = { setStage(Stage.RestoreRecovery) },
                onClose = onClose,
            )
        }
        Stage.RestoreRecovery -> {
            KeepAliveBackHandler("aegis.Root.RestoreRecovery")
            RestoreFromRecoveryFileScreen(
                onKekRecovered = { kek ->
                    // The file yielded the KEK (the user typed nothing). Rebind
                    // the vault under a fresh device key behind a biometric prompt.
                    rebindVaultFromKek(
                        activity = activity,
                        ctx = ctx,
                        recoveredKek = kek, // ownership transferred; wiped inside
                        onRebound = { v ->
                            setUnlocked(v)
                            setStage(if (pendingImport != null) Stage.Add else Stage.List)
                        },
                        onError = { msg ->
                            Toast.makeText(ctx, msg, Toast.LENGTH_LONG).show()
                        },
                    )
                },
                onBack = { setStage(if (unlockedRef() != null) Stage.List else Stage.Recovery) },
            )
        }
        Stage.List -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            KeepAliveBackHandler("aegis.Root.List")
            ListScreen(
                vault = v,
                onAdd = { setStage(Stage.Add) },
                onExport = { setStage(Stage.Export) },
                onImport = { setStage(Stage.RestoreRecovery) },
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
        return ctx.getString(R.string.err_no_screen_lock)
    }
    val bm = BiometricManager.from(ctx)
    val canAuth = bm.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
    )
    if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
        return ctx.getString(R.string.err_biometric_unavailable, canAuth)
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

    SuiteScaffold(
        title = stringResource(R.string.title_setup),
        showSuiteFooter = SHOW_SUITE_FOOTER,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            if (deviceIssue != null) {
                SuiteCard {
                    Text(
                        deviceIssue,
                        style = MaterialTheme.typography.bodyMedium,
                        color = UnderstoryTheme.semantic.warning,
                    )
                }
                SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.action_close))
                }
                return@Column
            }
            when (step) {
                0 -> {
                    Text(
                        stringResource(R.string.setup_intro),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    SuiteCard {
                        Text(
                            stringResource(R.string.setup_backup_note),
                            style = MaterialTheme.typography.bodyMedium,
                            color = UnderstoryTheme.semantic.warning,
                        )
                    }
                    SecureButton(onClick = { step = 1 }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.action_self_generate))
                    }
                    SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.action_cancel))
                    }
                }
                1 -> {
                    Text(
                        stringResource(R.string.setup_authenticate),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    error?.let {
                        Text(it, style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error)
                    }
                    LaunchedEffect(Unit) {
                        runCatching {
                            val cipher = Crypto.deviceAuthCipherForEncrypt()
                            promptAuth(activity, "Bind Understory OTP vault to this device", cipher,
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
                                    }.onFailure { error = ctx.getString(R.string.err_setup_failed, it.message ?: "") }
                                },
                                onError = { msg -> error = ctx.getString(R.string.err_auth_failed, msg) },
                                onCancel = { error = ctx.getString(R.string.msg_auth_cancelled); step = 0 },
                            )
                        }.onFailure { error = ctx.getString(R.string.err_crypto_init, it.message ?: "") }
                    }
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

    SuiteScaffold(
        title = stringResource(R.string.title_unlock),
        showSuiteFooter = SHOW_SUITE_FOOTER,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                stringResource(R.string.unlock_authenticate),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            error?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error)
            }

            SecureButton(
                onClick = {
                    if (working) return@SecureButton
                    working = true; error = null
                    runCatching {
                        val iv = AegisVault.ivForUnlock(ctx)
                        val cipher = Crypto.deviceAuthCipherForDecrypt(iv)
                        promptAuth(activity, "Unlock Understory OTP vault", cipher,
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
                                    else error = ctx.getString(R.string.err_vault_decrypt)
                                }
                            },
                            onError = { msg ->
                                error = ctx.getString(R.string.err_auth_failed, msg); working = false
                            },
                            onCancel = {
                                error = ctx.getString(R.string.msg_auth_cancelled); working = false
                            },
                        )
                    }.onFailure { t ->
                        working = false
                        if (VaultRecovery.classifyUnlockFailure(t) ==
                            VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED
                        ) onInvalidated()
                        else error = ctx.getString(R.string.err_crypto_init, t.message ?: "")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (working) stringResource(R.string.action_authenticating)
                    else stringResource(R.string.action_unlock),
                )
            }
            SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.action_close))
            }
        }
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
        .setSubtitle("Understory OTP vault")
        .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        .build()
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

/**
 * Rebuild the vault from recovered KEK material (self-sealing recovery, operator
 * directive 2026-07-03). Shared by the SILENT in-vault re-bind (KEK from the
 * at-rest sealed kit) and the "Restore from your recovery file" path (KEK from
 * the imported `.ukit`). The user typed nothing to get here.
 *
 * The old device-auth key was destroyed by the biometric / lock-screen change,
 * so we drop the stale alias and mint a FRESH one behind a BiometricPrompt, then
 * re-wrap the same KEK under it via [AegisVault.rebindWithKek] (or, on a device
 * with no vault file yet, [AegisVault.createWithKek]).
 *
 * [recoveredKek] ownership is TRANSFERRED to this function: it is wiped here
 * regardless of outcome.
 */
private fun rebindVaultFromKek(
    activity: FragmentActivity,
    ctx: Context,
    recoveredKek: ByteArray,
    onRebound: (UnlockedAegisVault) -> Unit,
    onError: (String) -> Unit,
) {
    runCatching {
        // Drop the stale (invalidated) device-auth key so a fresh, usable one is
        // minted; without this the Keystore hands back the destroyed key and
        // doFinal throws.
        Crypto.deleteDeviceAuthKey()
        val cipher = Crypto.deviceAuthCipherForEncrypt()
        promptAuth(
            activity,
            "Re-bind Understory OTP vault to this device",
            cipher,
            onSuccess = { authed ->
                val outcome = runCatching {
                    if (AegisVault.exists(ctx)) {
                        AegisVault.rebindWithKek(ctx, recoveredKek, authed)
                    } else {
                        AegisVault.createWithKek(ctx, recoveredKek, authed)
                    }
                }
                Crypto.wipe(recoveredKek)
                outcome.fold(
                    onSuccess = { v ->
                        if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                            onRebound(v)
                        } else {
                            v.lock()
                        }
                    },
                    onFailure = { onError(ctx.getString(R.string.err_vault_decrypt)) },
                )
            },
            onError = { msg ->
                Crypto.wipe(recoveredKek)
                onError(ctx.getString(R.string.err_auth_failed, msg))
            },
            onCancel = { Crypto.wipe(recoveredKek) },
        )
    }.onFailure {
        Crypto.wipe(recoveredKek)
        onError(ctx.getString(R.string.err_crypto_init, it.message ?: ""))
    }
}

/** Top-level sections of the authenticator, surfaced as a Material3 NavigationBar. */
private enum class ListTab { Codes, Settings }

@OptIn(ExperimentalMaterial3Api::class)
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
    // a11y service is enabled, our codes would leak. The banner makes the
    // threat surface explicit.
    val a11yState = remember { A11yProbe.check(ctx) }

    // Overlay-attack sentinel (OverlaySentinel): READ-ONLY, FAIL-OPEN. Only does
    // anything when an elevated shell is granted; otherwise it stays Inactive and
    // no banner shows (FLAG_SECURE still protects the screen — no dead control).
    // Re-scans each visible second alongside the code countdown, so a mid-session
    // overlay is caught. Any parse miss degrades silently to Inactive.
    var overlayResult by remember {
        mutableStateOf<OverlaySentinel.Result>(OverlaySentinel.Result.Inactive)
    }
    LaunchedEffect(tickSeconds) {
        overlayResult = OverlaySentinel.scan(ctx)
    }

    // Long-press on a row stages the entry for deletion. Confirmation
    // happens in an AlertDialog — accidental long-press is non-destructive.
    var deleteCandidate by remember { mutableStateOf<AegisEntry?>(null) }
    // Re-render trigger after a delete, since vault.contents is a var on
    // the unlocked vault and Compose otherwise won't observe the swap.
    var revision by remember { mutableStateOf(0) }

    var tab by rememberSaveable { mutableStateOf(ListTab.Codes.name) }
    val currentTab = ListTab.valueOf(tab)

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge) },
                actions = {
                    IconButtonSecure(
                        onClick = onLock,
                        icon = Icons.Filled.Lock,
                        contentDescription = stringResource(R.string.action_lock),
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurface,
                ),
            )
        },
        floatingActionButton = {
            // Primary create action — an add FAB, only where it belongs (Codes tab).
            if (currentTab == ListTab.Codes) {
                ExtendedFloatingActionButton(
                    onClick = onAdd,
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text(stringResource(R.string.action_add_entry)) },
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                )
            }
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
            ) {
                NavigationBarItem(
                    selected = currentTab == ListTab.Codes,
                    onClick = { tab = ListTab.Codes.name },
                    icon = { Icon(Icons.Filled.Shield, contentDescription = null) },
                    label = { Text(stringResource(R.string.nav_codes)) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        selectedTextColor = MaterialTheme.colorScheme.onSurface,
                        indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                    ),
                )
                NavigationBarItem(
                    selected = currentTab == ListTab.Settings,
                    onClick = { tab = ListTab.Settings.name },
                    icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                    label = { Text(stringResource(R.string.nav_settings)) },
                    colors = NavigationBarItemDefaults.colors(
                        selectedIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        selectedTextColor = MaterialTheme.colorScheme.onSurface,
                        indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                    ),
                )
            }
        },
        containerColor = MaterialTheme.colorScheme.background,
    ) { pad ->
        when (currentTab) {
            ListTab.Codes -> CodesTab(
                vault = vault,
                pad = pad,
                tickSeconds = tickSeconds,
                a11yState = a11yState,
                nudgeDismissed = nudgeDismissed,
                onDismissNudge = { nudgeDismissed = true },
                onExport = onExport,
                revision = revision,
                overlayResult = overlayResult,
                onReviewOverlay = { openOverlaySettings(ctx) },
                onReviewA11y = { A11yProbe.openA11ySettings(ctx) },
                onCopyTotp = { entry, code ->
                    // Copy window = the entry's real period, and the toast reads the
                    // SAME number (one source of truth, design §5.4).
                    copyCodeToClipboard(ctx, code, windowSeconds = entry.period)
                    Toast.makeText(ctx, ctx.getString(R.string.msg_code_copied_totp, entry.period),
                        Toast.LENGTH_SHORT).show()
                },
                onGenerateHotp = { entry ->
                    runCatching {
                        // Advance + persist BEFORE copying; propagate on save failure
                        // (no code served on desync).
                        val code = AegisCode.advanceHotp(vault, entry)
                        copyCodeToClipboard(ctx, code, windowSeconds = 60)
                        revision++
                        Toast.makeText(
                            ctx,
                            ctx.getString(R.string.msg_code_copied_hotp, entry.counter + 1),
                            Toast.LENGTH_SHORT,
                        ).show()
                    }.onFailure {
                        Toast.makeText(ctx, ctx.getString(R.string.err_generate_failed, it.message ?: ""), Toast.LENGTH_LONG).show()
                    }
                },
                onLongPressEntry = { deleteCandidate = it },
            )
            ListTab.Settings -> SettingsTab(
                pad = pad,
                onExport = onExport,
                onImport = onImport,
                onKeyboard = onKeyboard,
                onDiagnostics = onDiagnostics,
            )
        }
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
            title = { Text(stringResource(R.string.dialog_delete_title)) },
            text = {
                val dialogView = LocalView.current
                DisposableEffect(dialogView) {
                    dialogView.filterTouchesWhenObscured = true
                    onDispose { /* dialog tears down with view; nothing to undo */ }
                }
                Column(verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                    Text(
                        entry.issuer.ifEmpty { stringResource(R.string.no_issuer) } +
                            (if (entry.account.isNotEmpty()) " — ${entry.account}" else ""),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        stringResource(R.string.dialog_delete_body),
                        style = MaterialTheme.typography.bodyMedium,
                        color = UnderstoryTheme.semantic.warning,
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
                        Toast.makeText(ctx, ctx.getString(R.string.msg_entry_deleted), Toast.LENGTH_SHORT).show()
                    }.onFailure {
                        Toast.makeText(ctx, ctx.getString(R.string.err_delete_failed, it.message ?: ""), Toast.LENGTH_LONG).show()
                    }
                }) {
                    Text(stringResource(R.string.action_delete), color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteCandidate = null }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

/**
 * The "Codes" tab: the scrollable authenticator list. Header line with the count
 * and an on-device security note (the honest, user-facing replacement for the
 * old dev status strip), any active warnings (a11y / export-first nudge), then a
 * card per account. Every code stays redacted; tap copies. A trailing spacer
 * keeps the last row clear of the FAB.
 */
@Composable
private fun CodesTab(
    vault: UnlockedAegisVault,
    pad: androidx.compose.foundation.layout.PaddingValues,
    tickSeconds: Long,
    a11yState: A11yProbe.State,
    nudgeDismissed: Boolean,
    onDismissNudge: () -> Unit,
    onExport: () -> Unit,
    revision: Int,
    overlayResult: OverlaySentinel.Result,
    onReviewOverlay: () -> Unit,
    onReviewA11y: () -> Unit,
    onCopyTotp: (AegisEntry, String) -> Unit,
    onGenerateHotp: (AegisEntry) -> Unit,
    onLongPressEntry: (AegisEntry) -> Unit,
) {
    val entries = vault.contents.entries
    if (entries.isEmpty()) {
        Column(modifier = Modifier.fillMaxSize().padding(pad)) {
            EmptyState(
                title = stringResource(R.string.empty_no_entries_title),
                body = stringResource(R.string.empty_no_entries_body),
                icon = Icons.Filled.Shield,
                modifier = Modifier.weight(1f),
            )
        }
        return
    }

    // revision is read so Compose treats the LazyColumn as dirty after a delete.
    @Suppress("UNUSED_EXPRESSION") revision
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(pad),
        contentPadding = PaddingValues(
            start = UnderstoryTheme.spacing.lg,
            end = UnderstoryTheme.spacing.lg,
            top = UnderstoryTheme.spacing.md,
            // Room so the FAB never overlaps the last card.
            bottom = UnderstoryTheme.spacing.xxl + 56.dp,
        ),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
    ) {
        item(key = "__header") {
            Column(verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Outlined.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp),
                    )
                    Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                    Text(
                        stringResource(R.string.on_device_note),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    stringResource(R.string.entries_count, entries.size),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        // Overlay-attack banner: only present when the sentinel positively
        // detected an untrusted app drawing over us (Active). Inactive — the
        // fail-open / unelevated / parse-miss state — renders nothing, leaving
        // the existing FLAG_SECURE posture untouched.
        (overlayResult as? OverlaySentinel.Result.Active)?.let { active ->
            item(key = "__overlay") {
                WarningCard(
                    text = stringResource(
                        R.string.overlay_warning,
                        active.packages.joinToString(", "),
                    ),
                    actionLabel = stringResource(R.string.overlay_warning_review),
                    onAction = onReviewOverlay,
                )
            }
        }

        if (a11yState.activeServiceCount > 0) {
            item(key = "__a11y") {
                WarningCard(
                    text = stringResource(R.string.a11y_warning, a11yState.activeServiceCount),
                    actionLabel = stringResource(R.string.action_review_a11y),
                    onAction = onReviewA11y,
                )
            }
        }

        // Export-first nudge: shown until dismissed. Ties recovery to §3 export.
        if (!nudgeDismissed) {
            item(key = "__nudge") {
                SuiteCard {
                    Text(
                        stringResource(R.string.nudge_export),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
                    ) {
                        SecureButton(onClick = onExport, modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.action_export))
                        }
                        SecureOutlinedButton(onClick = onDismissNudge, modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.action_later))
                        }
                    }
                }
            }
        }

        items(entries, key = { it.id }) { entry ->
            if (entry.type == OtpAuthEntry.Type.HOTP) {
                HotpRow(
                    entry = entry,
                    onGenerate = { onGenerateHotp(entry) },
                    onLongPress = { onLongPressEntry(entry) },
                )
            } else {
                EntryRow(
                    entry = entry,
                    nowSeconds = tickSeconds,
                    onTap = { code -> onCopyTotp(entry, code) },
                    onLongPress = { onLongPressEntry(entry) },
                )
            }
        }
    }
}

/**
 * The "Settings" tab: backup / restore / keyboard grouped under section headers
 * as tappable list rows with leading icons and supporting copy. The Diagnostics
 * row is ENG-ONLY — [BuildConfig.FLAVOR] gates it so the shipping (prod) build
 * exposes no diagnostics affordance at all.
 */
@Composable
private fun SettingsTab(
    pad: androidx.compose.foundation.layout.PaddingValues,
    onExport: () -> Unit,
    onImport: () -> Unit,
    onKeyboard: () -> Unit,
    onDiagnostics: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(pad)
            .verticalScroll(rememberScrollState())
            .padding(bottom = UnderstoryTheme.spacing.xl),
    ) {
        SuiteSectionHeader(stringResource(R.string.settings_section_backup))
        SuiteListRow(
            headline = stringResource(R.string.settings_export_title),
            supporting = stringResource(R.string.settings_export_supporting),
            leading = { SettingsLeadingIcon(Icons.Outlined.CloudUpload) },
            onClick = onExport,
        )
        SuiteListRow(
            headline = stringResource(R.string.settings_restore_title),
            supporting = stringResource(R.string.settings_restore_supporting),
            leading = { SettingsLeadingIcon(Icons.Outlined.CloudDownload) },
            onClick = onImport,
        )

        SuiteSectionHeader(stringResource(R.string.settings_section_input))
        SuiteListRow(
            headline = stringResource(R.string.settings_keyboard_title),
            supporting = stringResource(R.string.settings_keyboard_supporting),
            leading = { SettingsLeadingIcon(Icons.Filled.Keyboard) },
            onClick = onKeyboard,
        )

        SuiteSectionHeader(stringResource(R.string.settings_section_about))
        SuiteListRow(
            headline = stringResource(R.string.settings_about_title),
            supporting = stringResource(R.string.settings_about_supporting),
            leading = { SettingsLeadingIcon(Icons.Outlined.Info) },
        )

        // ENG-ONLY: the in-app Diagnostics event log. Gated on the product
        // flavor so prod builds ship with zero diagnostics entry point. The
        // DiagnosticsScreen code stays reachable in the eng flavor.
        if (BuildConfig.FLAVOR == "eng") {
            SuiteListRow(
                headline = stringResource(R.string.action_diagnostics),
                supporting = stringResource(R.string.settings_diagnostics_supporting),
                leading = { SettingsLeadingIcon(Icons.Filled.Key) },
                onClick = onDiagnostics,
            )
        }
    }
}

@Composable
private fun SettingsLeadingIcon(icon: androidx.compose.ui.graphics.vector.ImageVector) {
    Icon(
        imageVector = icon,
        contentDescription = null, // headline carries the meaning
        tint = MaterialTheme.colorScheme.primary,
    )
}

/** A warning-tinted card with a message and an inline review action. */
@Composable
private fun WarningCard(text: String, actionLabel: String, onAction: () -> Unit) {
    SuiteCard {
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = UnderstoryTheme.semantic.warning,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        SecureOutlinedButton(onClick = onAction, modifier = Modifier.fillMaxWidth()) {
            Text(actionLabel)
        }
    }
}

/**
 * Surface the system "draw over other apps" screen so the user can review /
 * revoke the offending app's overlay permission themselves. Read-only routing —
 * aegis does not revoke on the user's behalf here (the sentinel is detection,
 * not enforcement). Falls back to the app's own details screen, then to the
 * top-level app-list settings, if the primary intent can't resolve.
 */
private fun openOverlaySettings(ctx: Context) {
    val intents = listOf(
        Intent(android.provider.Settings.ACTION_MANAGE_OVERLAY_PERMISSION),
        Intent(android.provider.Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS),
    )
    for (intent in intents) {
        val ok = runCatching {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(intent)
            true
        }.getOrDefault(false)
        if (ok) return
    }
}

/** Top-bar icon action with the suite's tap-jacking-hardened click filter. */
@Composable
private fun IconButtonSecure(
    onClick: () -> Unit,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    contentDescription: String,
) {
    Box(
        modifier = Modifier
            .size(48.dp)
            .secureClickable(onClick)
            .semantics { this.contentDescription = contentDescription },
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null, // Box carries the description
            tint = MaterialTheme.colorScheme.onSurface,
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
    val issuerText = entry.issuer.ifEmpty { stringResource(R.string.no_issuer) }
    val rowDesc = stringResource(R.string.cd_totp_row, issuerText, entry.account)

    // Threat model: "screen is never secure even when device is" — codes are
    // NEVER rendered to screen. Tap copies the current code to the clipboard;
    // the row display stays redacted (large grouped bullets, not the digits).
    SuiteCard(onClick = null) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .combinedClickable(
                    onClick = { onTap(code) },
                    onLongClick = onLongPress,
                )
                .semantics(mergeDescendants = true) { contentDescription = rowDesc },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IssuerAvatar(issuer = entry.issuer)
            Spacer(Modifier.width(UnderstoryTheme.spacing.md))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    issuerText,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                )
                if (entry.account.isNotEmpty()) {
                    Text(
                        entry.account,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    )
                }
                Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
                // Large, grouped, easy-to-read redacted code display. The bullets
                // are spaced exactly like a real code of this digit-count would be,
                // so the row is stable and the actual digits never reach the tree.
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = AegisCode.bullets(entry.digits),
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.primary,
                        letterSpacing = 2.sp,
                        modifier = Modifier.clearAndSetSemantics {},
                    )
                    Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                    Icon(
                        imageVector = Icons.Filled.ContentCopy,
                        contentDescription = null, // row description covers the copy action
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(16.dp),
                    )
                }
            }
            Spacer(Modifier.width(UnderstoryTheme.spacing.md))
            CountdownRing(
                secondsLeft = secondsLeft,
                period = entry.period,
            )
        }
    }
}

/**
 * Circular issuer monogram: the issuer's first letter on a tonal disc. Purely
 * decorative — the row's merged content description names the issuer for
 * TalkBack, so this Box clears its own semantics.
 */
@Composable
private fun IssuerAvatar(issuer: String) {
    val letter = issuer.trim().firstOrNull()?.uppercaseChar()?.toString() ?: "•"
    // Tonal disc from the app accent (theme primary) — keeps every badge inside
    // the dim/desaturated suite palette rather than inventing per-issuer hues.
    val base = MaterialTheme.colorScheme.primary
    val container = base.copy(alpha = 0.18f)
    Box(
        modifier = Modifier
            .size(40.dp)
            .background(container, CircleShape)
            .clearAndSetSemantics {},
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = letter,
            style = MaterialTheme.typography.titleMedium,
            color = base,
        )
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
    val issuerText = entry.issuer.ifEmpty { stringResource(R.string.no_issuer) }
    val rowDesc = stringResource(R.string.cd_hotp_row, issuerText, entry.account)
    val accountPrefix = if (entry.account.isNotEmpty())
        stringResource(R.string.hotp_meta_account, entry.account) else ""
    SuiteCard(onClick = null) {
        // The label column is long-pressable to delete and carries the row
        // description; the "Generate next code" button stays a SEPARATE a11y
        // node (not merged) so TalkBack can reach it as its own action.
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IssuerAvatar(issuer = entry.issuer)
            Spacer(Modifier.width(UnderstoryTheme.spacing.md))
            Column(
                modifier = Modifier
                    .weight(1f)
                    .combinedClickable(
                        onClick = { /* HOTP action is the explicit button, not the row */ },
                        onLongClick = onLongPress,
                    )
                    .semantics(mergeDescendants = true) { contentDescription = rowDesc },
            ) {
                Text(
                    issuerText,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                )
                Text(
                    stringResource(R.string.hotp_meta, accountPrefix, entry.counter),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            val genCd = stringResource(R.string.cd_generate_next)
            SecureButton(
                onClick = onGenerate,
                modifier = Modifier.semantics { contentDescription = genCd },
            ) {
                Icon(
                    imageVector = Icons.Filled.Refresh,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                Text(stringResource(R.string.action_generate_next))
            }
        }
    }
}

/**
 * Circular countdown indicator. The ring shrinks from full → empty over the
 * TOTP period; color shifts success → warning → error as the window expires.
 * The numeric seconds-left is shown inside the ring. Colors come from the
 * shared semantic token roles.
 */
@Composable
private fun CountdownRing(secondsLeft: Int, period: Int) {
    val color = colorForCountdown(secondsLeft)
    val ringBg = MaterialTheme.colorScheme.surfaceVariant
    val cd = stringResource(R.string.cd_countdown, secondsLeft)
    Box(
        modifier = Modifier
            .size(34.dp)
            .semantics { contentDescription = cd },
        contentAlignment = Alignment.Center,
    ) {
        androidx.compose.foundation.Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = 3.dp.toPx()
            val sweepFraction = secondsLeft.toFloat() / period.coerceAtLeast(1)
            // Background ring (dim).
            drawArc(
                color = ringBg,
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
            style = MaterialTheme.typography.labelMedium,
            color = color,
            modifier = Modifier.clearAndSetSemantics {},
        )
    }
}

@Composable
private fun colorForCountdown(seconds: Int): Color = when {
    seconds <= 5 -> MaterialTheme.colorScheme.error
    seconds <= 10 -> UnderstoryTheme.semantic.warning
    else -> UnderstoryTheme.semantic.success
}

/**
 * Copy a code to the system clipboard with the sensitive flag and a best-effort
 * auto-clear at [windowSeconds] — the SAME number the call site's toast
 * advertises (one source of truth, design §5.4). The clear is scheduled on a
 * main-thread Handler and is NOT guaranteed to run if the app process is killed
 * first; the toast copy says so honestly (CD-4e).
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
                qrFeedback = ctx.getString(R.string.msg_qr_no_code)
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
                        return@runCatching ctx.getString(R.string.msg_google_empty)
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
                        ctx.getString(R.string.msg_google_batch, import.batchIndex + 1, import.batchSize)
                    } else ""
                    ctx.getString(R.string.msg_google_imported, result.added, result.skipped, batchNote)
                }
                qrFeedback = outcome.getOrElse { ctx.getString(R.string.err_google_parse, it.message ?: "") }
                working = false
                return@launch
            }

            // Standard otpauth:// or raw secret path.
            secretInput = decoded
            qrFeedback = ctx.getString(R.string.msg_qr_decoded)
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
                    return@runCatching ctx.getString(R.string.msg_no_entries_in_file, errs)
                }
                val result = AegisMerge.merge(vault.contents.entries, summary.entries)
                summary.entries.forEach { it.wipeSecret() }
                if (result.added > 0) {
                    vault.contents = vault.contents.copy(entries = result.merged)
                    withContext(Bg.io) { vault.save() }
                }
                val errPart = if (summary.errorCount > 0) " — ${summary.errorCount} parse error${if (summary.errorCount == 1) "" else "s"} skipped" else ""
                val batchPart = summary.multiBatchHint?.let { " ($it)" } ?: ""
                ctx.getString(R.string.msg_file_imported, result.added, result.skipped, errPart, batchPart)
            }
            qrFeedback = outcome.getOrElse { ctx.getString(R.string.err_import_failed, it.message ?: it.javaClass.simpleName) }
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

    SuiteScaffold(
        title = stringResource(R.string.title_add),
        onBack = onCancel,
        showSuiteFooter = SHOW_SUITE_FOOTER,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm),
        ) {
            Text(
                stringResource(R.string.add_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            SecureOutlinedButton(
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
                Text(stringResource(R.string.action_pick_qr))
            }
            SecureOutlinedButton(
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
                Text(stringResource(R.string.action_import_file))
            }
            if (working) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                    )
                    Spacer(Modifier.width(UnderstoryTheme.spacing.md))
                    Text(stringResource(R.string.state_working),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            qrFeedback?.let {
                val decodedMsg = stringResource(R.string.msg_qr_decoded)
                Text(
                    it,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (it == decodedMsg) UnderstoryTheme.semantic.success
                    else UnderstoryTheme.semantic.warning,
                )
            }
            OutlinedTextField(
                value = issuer, onValueChange = { issuer = it },
                label = { Text(stringResource(R.string.label_issuer)) }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = account, onValueChange = { account = it },
                label = { Text(stringResource(R.string.label_account)) }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            // Mask the secret / otpauth:// field by default (design §5.3 D-S3) — it
            // holds the seed, and rendering it in plaintext after paste/QR decode is
            // inconsistent with redacting codes everywhere else. Eye toggle to
            // reveal for verification.
            OutlinedTextField(
                value = secretInput, onValueChange = { secretInput = it },
                label = { Text(stringResource(R.string.label_secret)) },
                visualTransformation = if (secretRevealed) VisualTransformation.None
                else PasswordVisualTransformation(),
                trailingIcon = {
                    TextButton(onClick = { secretRevealed = !secretRevealed }) {
                        Text(
                            if (secretRevealed) stringResource(R.string.action_hide)
                            else stringResource(R.string.action_show),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth().height(120.dp),
            )
            error?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error)
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.sm)) {
                SecureButton(
                    onClick = {
                        error = null
                        val parsed = try {
                            OtpAuthEntry.parse(secretInput.trim())
                        } catch (t: Throwable) {
                            error = ctx.getString(R.string.err_parse_input, t.message ?: ctx.getString(R.string.err_parse_generic))
                            return@SecureButton
                        }
                        val finalIssuer = issuer.trim().ifEmpty { parsed.issuer }
                        val finalAccount = account.trim().ifEmpty { parsed.account }
                        if (parsed.secret.isEmpty()) {
                            parsed.wipeSecret()
                            error = ctx.getString(R.string.err_secret_empty)
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
                                onFailure = { error = ctx.getString(R.string.err_save_failed, it.message ?: "") },
                            )
                        }
                    },
                    enabled = secretInput.isNotBlank() && !working,
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.action_save))
                }
                SecureOutlinedButton(onClick = {
                    // Same secret-reference-drop on Cancel.
                    secretInput = ""
                    issuer = ""
                    account = ""
                    onCancel()
                }, modifier = Modifier.weight(1f).fillMaxWidth()) {
                    Text(stringResource(R.string.action_cancel))
                }
            }
        }
    }
}
