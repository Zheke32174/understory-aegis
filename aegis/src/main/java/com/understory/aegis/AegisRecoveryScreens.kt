package com.understory.aegis

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.inputmethod.InputMethodManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.understory.backup.RecoveryFile
import com.understory.security.RecoveryCopy
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.VaultRecoveryScreen
import com.understory.security.ui.Bg
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.messageForUser
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * aegis Recovery landing (design §4.2), reworked to the SELF-SEALING,
 * FILE-BASED recovery model (operator directive 2026-07-03 — "the screen is the
 * enemy"). Reached when the device-auth key was destroyed (biometric /
 * lock-screen change) — the encrypted entries can no longer be opened under the
 * old key on this device.
 *
 * The user NEVER types a recovery key. The honest paths are:
 *   1. Restore from your recovery file — SAF-import the opaque recovery file the
 *      user exported earlier; the app reads `R` from the file and rebuilds the
 *      vault ([onRestoreFromFile]). No typing, nothing shown.
 *   2. Reset — wipe and start over.
 *
 * The SILENT in-vault re-bind (from the at-rest sealed kit) is attempted FIRST,
 * before this screen is ever shown, by [MainActivity]'s Recovery stage; this
 * landing is only reached when that silent path returned null (kit gone).
 *
 * Reset delegates to the shared [VaultRecoveryScreen] with keyUsable=false (the
 * key is gone, so export-first is impossible) driving [AegisResetHooks].
 */
@Composable
fun RecoveryScreen(
    onReset: () -> Unit,
    onRestoreFromFile: () -> Unit,
    onClose: () -> Unit,
) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        var resetting by remember { mutableStateOf(false) }
        if (resetting) {
            VaultRecoveryScreen(
                keyUsable = false,
                appName = "OTP",
                hooks = AegisResetHooks(onSetup = onReset),
            )
            return@UnderstoryTheme
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                RecoveryCopy.INVALIDATED_TITLE,
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                "Your fingerprint or screen lock changed, so this vault can't be opened " +
                    "the usual way. Restore it from the recovery file you exported earlier — " +
                    "you won't need to type anything.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(4.dp))
            SecureButton(onClick = onRestoreFromFile, modifier = Modifier.fillMaxWidth()) {
                Text("Restore from your recovery file")
            }
            SecureOutlinedButton(onClick = { resetting = true }, modifier = Modifier.fillMaxWidth()) {
                Text(RecoveryCopy.RESET_TITLE)
            }
            SecureOutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) {
                Text("Close")
            }
        }
    }
}

/**
 * Restore from an exported recovery file (operator directive 2026-07-03). SAF
 * `OpenDocument` the opaque `.ukit`, read the KEK material from it via
 * [RecoveryFile.importKit] off-thread (the file carries its own recovery secret
 * `R` — the user types NOTHING), then hand the recovered KEK to [onKekRecovered],
 * which authenticates via BiometricPrompt and rebuilds the vault under a fresh
 * device key. Nothing secret is ever rendered.
 *
 * @param onKekRecovered receives the recovered KEK material (the callee OWNS and
 *                       must wipe it) and drives the biometric rebind.
 */
@Composable
fun RestoreFromRecoveryFileScreen(
    onKekRecovered: (ByteArray) -> Unit,
    onBack: () -> Unit,
) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        val ctx = LocalContext.current
        val scope = rememberCoroutineScope()

        var phaseName by rememberSaveable { mutableStateOf(RestorePhase.PICK.name) }
        val phase = RestorePhase.valueOf(phaseName)
        var message by remember { mutableStateOf("") }

        val openDoc = rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocument(),
        ) { uri: Uri? ->
            if (uri == null) return@rememberLauncherForActivityResult
            phaseName = RestorePhase.READING.name
            scope.launch {
                val outcome = runCatching {
                    withContext(Bg.io) {
                        ctx.contentResolver.openInputStream(uri)?.use { input ->
                            RecoveryFile.importKit(input)
                        } ?: error("Could not open the chosen file.")
                    }
                }
                outcome.fold(
                    // Hand the recovered KEK to the biometric rebind. Leave the
                    // phase on READING so the screen shows progress while the
                    // prompt runs; MainActivity routes away on success.
                    onSuccess = { kek -> onKekRecovered(kek) },
                    onFailure = {
                        // Wrong/corrupt file or GCM auth failure — one honest line.
                        message = "That file isn't a valid recovery file for this vault."
                        phaseName = RestorePhase.ERROR.name
                    },
                )
            }
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                "Restore from your recovery file",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            when (phase) {
                RestorePhase.PICK -> {
                    Text(
                        "Pick the recovery file you exported earlier. aegis reads it and " +
                            "rebuilds your vault — you don't type anything.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    SecureButton(
                        onClick = { openDoc.launch(arrayOf("application/octet-stream", "*/*")) },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Choose recovery file") }
                    SecureOutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                        Text("Back")
                    }
                }
                RestorePhase.READING -> {
                    Text("Reading recovery file…", style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    CircularProgressIndicator()
                }
                RestorePhase.ERROR -> {
                    Text(message, style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(4.dp))
                    SecureButton(
                        onClick = { phaseName = RestorePhase.PICK.name },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Try again") }
                    SecureOutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                        Text("Back")
                    }
                }
            }
        }
    }
}

private enum class RestorePhase { PICK, READING, ERROR }

/**
 * IME enablement UX (design §2.4, A-F3/D-S4). Mirrors passgen's proven flow:
 * detect whether the aegis keyboard is enabled, offer "Enable in system
 * settings" and "Switch keyboard now", and NEVER set the default
 * programmatically (CD-2c). NEW screen, token-native.
 */
@Composable
fun KeyboardEnablementScreen(onBack: () -> Unit) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        val ctx = LocalContext.current
        val imm = remember { ctx.getSystemService(InputMethodManager::class.java) }
        // Enabled iff our IME component id appears in the enabled list.
        val enabled = remember {
            runCatching {
                imm?.enabledInputMethodList?.any {
                    it.packageName == ctx.packageName
                } ?: false
            }.getOrDefault(false)
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                "aegis keyboard",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                "Type codes without the clipboard. Your Samsung/Gboard keyboard stays your " +
                    "default; aegis is switched to only when you need a code, and switches back " +
                    "automatically.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SuiteCard {
                Text(
                    "Accessibility note: the aegis keyboard is not TalkBack-navigable by design " +
                        "(an anti-scrape posture). If you rely on a screen reader, use tap-to-copy " +
                        "in the app instead.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(4.dp))
            if (enabled) {
                Text(
                    "aegis keyboard is enabled.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = UnderstoryTheme.semantic.success,
                )
            } else {
                SecureButton(
                    onClick = {
                        runCatching {
                            ctx.startActivity(
                                Intent(Settings.ACTION_INPUT_METHOD_SETTINGS)
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                            )
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Enable in system settings") }
            }
            SecureOutlinedButton(
                onClick = { runCatching { imm?.showInputMethodPicker() } },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Switch keyboard now") }
            SecureOutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Back")
            }
        }
    }
}
