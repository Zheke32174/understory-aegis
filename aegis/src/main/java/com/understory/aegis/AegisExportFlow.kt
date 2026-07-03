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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.understory.security.Crypto
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.VaultExportScreen
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme

/**
 * aegis's Export flow (design §3.1 output #3 / §4).
 *
 * THREAT-MODEL INVARIANT (screen-emanation defense): the value that can
 * decrypt a backup is NEVER rendered on screen — not as text, not grouped
 * for transcription, not as a QR code. A camera or Van-Eck capture of the
 * display would otherwise leak the ultimate secret, which FLAG_SECURE does
 * not prevent. So instead of minting a random recovery key and revealing it,
 * the user SUPPLIES a recovery passphrase (masked entry, never displayed or
 * stored). That passphrase encrypts the `.usbe` and is what the user types
 * on restore. Losing it means the backup is useless (honest §4).
 *
 * The plaintext-interop path ([onExportPlaintext]) offers the otpauth:// list
 * and Aegis-compatible JSON outputs (#1/#2).
 *
 * The passphrase CharArray handed to the export screen is owned here and wiped
 * on dispose.
 */
@Composable
fun AegisExportFlow(
    vault: UnlockedAegisVault,
    onExportPlaintext: () -> Unit,
    onDone: () -> Unit,
) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        var passphrase by remember { mutableStateOf("") }
        var confirm by remember { mutableStateOf("") }
        var committed by remember { mutableStateOf(false) }

        if (!committed) {
            RecoveryPassphraseEntry(
                passphrase = passphrase,
                onPassphrase = { passphrase = it },
                confirm = confirm,
                onConfirm = { confirm = it },
                onProceed = { committed = true },
                onCancel = onDone,
            )
        } else {
            // Hand the RAW passphrase chars to the shared encrypted-export
            // screen (VaultImportScreen decrypts with the raw typed value, so
            // encrypt must match — do NOT normalize here).
            val keyChars = remember { passphrase.toCharArray() }
            DisposableEffect(Unit) { onDispose { Crypto.wipe(keyChars) } }
            VaultExportScreen(
                port = AegisExportPort,
                unlocked = vault,
                recoveryKey = keyChars,
                onDone = onDone,
                onExportPlaintext = onExportPlaintext,
            )
        }
    }
}

private const val MIN_PASSPHRASE_LEN = 8

/**
 * Collect a recovery passphrase the user chooses. Both fields are masked;
 * nothing secret is ever rendered. The user is supplying their own secret
 * (the accepted password-entry pattern), not the app emanating a stored one.
 */
@Composable
private fun RecoveryPassphraseEntry(
    passphrase: String,
    onPassphrase: (String) -> Unit,
    confirm: String,
    onConfirm: (String) -> Unit,
    onProceed: () -> Unit,
    onCancel: () -> Unit,
) {
    val longEnough = passphrase.length >= MIN_PASSPHRASE_LEN
    val matches = passphrase == confirm
    val valid = longEnough && matches
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(UnderstoryTheme.spacing.lg),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
    ) {
        Text(
            "Set a recovery passphrase",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Text(
            "This passphrase encrypts your backup file. It is never shown on " +
                "screen or stored anywhere — if you lose it, the backup cannot " +
                "be opened. Choose something strong you'll remember, or keep it " +
                "in your password manager.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = onPassphrase,
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            label = { Text("Recovery passphrase") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = confirm,
            onValueChange = onConfirm,
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            label = { Text("Confirm passphrase") },
            modifier = Modifier.fillMaxWidth(),
        )
        if (passphrase.isNotEmpty() && !longEnough) {
            Text(
                "Use at least $MIN_PASSPHRASE_LEN characters.",
                style = MaterialTheme.typography.bodySmall,
                color = UnderstoryTheme.semantic.warning,
            )
        } else if (confirm.isNotEmpty() && !matches) {
            Text(
                "The two entries don't match.",
                style = MaterialTheme.typography.bodySmall,
                color = UnderstoryTheme.semantic.warning,
            )
        }
        Spacer(Modifier.height(4.dp))
        SecureButton(
            onClick = onProceed,
            enabled = valid,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Continue to export") }
        SecureOutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
            Text("Cancel")
        }
    }
}
