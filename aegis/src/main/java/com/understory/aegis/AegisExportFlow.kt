package com.understory.aegis

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
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.understory.security.RecoveryCopy
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.VaultExportScreen
import com.understory.security.VaultRecovery
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * aegis's Export flow (design §3.1 output #3 / §4). NEW screen — authored
 * token-native with the shared components + [UnderstoryTheme] per the wave-2
 * rule. Wraps the shared [VaultExportScreen]:
 *
 *   1. Mint a fresh recovery key ([VaultRecovery.newRecoveryKey]).
 *   2. REVEAL it once (grouped, off-device-save guidance). The user confirms
 *      they saved it — this is the ONLY thing that can decrypt the export, so
 *      losing it means the backup is useless (honest §4).
 *   3. Hand the key to the shared encrypted-export screen, which writes the
 *      `.usbe` under it. The plaintext-interop path ([onExportPlaintext])
 *      offers the otpauth:// list and Aegis-compatible JSON outputs (#1/#2).
 *
 * The recovery key CharArray is owned here and wiped on dispose.
 */
@Composable
fun AegisExportFlow(
    vault: UnlockedAegisVault,
    onExportPlaintext: () -> Unit,
    onDone: () -> Unit,
) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        // Mint once per entry into this flow. Key lifecycle is owned here.
        val recoveryKey = remember { VaultRecovery.newRecoveryKey() }
        DisposableEffect(Unit) { onDispose { recoveryKey.wipe() } }

        var confirmed by remember { mutableStateOf(false) }

        if (!confirmed) {
            RecoveryKeyReveal(
                keyChars = recoveryKey.chars,
                onConfirmed = { confirmed = true },
                onCancel = onDone,
            )
        } else {
            VaultExportScreen(
                port = AegisExportPort,
                unlocked = vault,
                recoveryKey = recoveryKey.chars,
                onDone = onDone,
                onExportPlaintext = onExportPlaintext,
            )
        }
    }
}

/**
 * One-time reveal of the freshly minted recovery key. Renders the grouped form
 * for transcription; the actual characters ARE shown here (this is the one
 * moment the user must capture them), but never announced by TalkBack via the
 * value — the SuiteCard reads its label. No clipboard button: per
 * [RecoveryCopy.CLIPBOARD_RECOVERY_KEY_WARNING] we steer to off-device saving.
 */
@Composable
private fun RecoveryKeyReveal(
    keyChars: CharArray,
    onConfirmed: () -> Unit,
    onCancel: () -> Unit,
) {
    val grouped = remember(keyChars) {
        com.understory.security.RecoveryKeyCodec.grouped(keyChars)
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(UnderstoryTheme.spacing.lg),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
    ) {
        Text(
            RecoveryCopy.RECOVERY_KEY_TITLE,
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Text(
            RecoveryCopy.RECOVERY_KEY_BODY,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SuiteCard {
            Text(
                grouped,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Text(
            RecoveryCopy.CLIPBOARD_RECOVERY_KEY_WARNING,
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.warning,
        )
        Text(
            RecoveryCopy.RECOVERY_KEY_CONFIRM,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(4.dp))
        SecureButton(onClick = onConfirmed, modifier = Modifier.fillMaxWidth()) {
            Text("I saved it — continue to export")
        }
        SecureOutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
            Text("Cancel")
        }
    }
}
