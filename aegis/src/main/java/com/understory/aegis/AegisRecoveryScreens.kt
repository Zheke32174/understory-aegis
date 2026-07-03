package com.understory.aegis

import android.content.Intent
import android.provider.Settings
import android.view.inputmethod.InputMethodManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.understory.security.RecoveryCopy
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.VaultRecoveryScreen
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * aegis Recovery landing (design §4.2). Reached when the device-auth key was
 * destroyed (biometric / lock-screen change) — the encrypted entries can no
 * longer be opened on this device. Two honest paths: restore from an Understory
 * backup, or reset to start over. NEW screen, token-native.
 *
 * Reset delegates to the shared [VaultRecoveryScreen] with keyUsable=false (the
 * key is gone, so export-first is impossible) driving [AegisResetHooks].
 */
@Composable
fun RecoveryScreen(
    onReset: () -> Unit,
    onRestore: () -> Unit,
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
                RecoveryCopy.INVALIDATED_BODY,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(4.dp))
            SecureButton(onClick = onRestore, modifier = Modifier.fillMaxWidth()) {
                Text("Restore from a backup file")
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
 * Shown when the user picks "Restore from backup" but the vault key is
 * invalidated (no unlockable vault to merge into). Honest instruction: reset
 * first, then restore. NEW screen, token-native.
 */
@Composable
fun RestoreNeedsResetScreen(
    onReset: () -> Unit,
    onBack: () -> Unit,
) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                RecoveryCopy.IMPORT_TITLE,
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                "This vault's key was destroyed, so there's nothing to restore into yet. " +
                    "Reset to create a fresh vault, then use Restore from the main screen to " +
                    "load your backup with its recovery key.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(4.dp))
            SecureButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
                Text("Reset and create a fresh vault")
            }
            SecureOutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Back")
            }
        }
    }
}

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
