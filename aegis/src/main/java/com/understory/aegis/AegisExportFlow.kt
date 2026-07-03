package com.understory.aegis

import android.net.Uri
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
import com.understory.security.Crypto
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.messageForUser
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * aegis's Export flow (design §3.1 / §4), reworked to the SELF-SEALING,
 * FILE-BASED recovery model (operator directive 2026-07-03 — "the screen is the
 * enemy").
 *
 * THREAT-MODEL INVARIANT: the value that can decrypt a vault is NEVER rendered on
 * screen — not as text, not grouped for transcription, not as a QR code — AND is
 * NEVER typed by the user. The app self-manages a random recovery key `R` as an
 * encrypted FILE:
 *
 *   - At vault creation the KEK is already sealed to an at-rest kit under a
 *     non-auth wrap key (see [AegisVault.createV2] → [RecoveryFile.seal]), so a
 *     biometric re-enrollment recovers SILENTLY with nothing on screen.
 *   - "Export recovery file" here writes ONE opaque, self-contained recovery file
 *     to a SAF location (USB, cloud). It carries `R` plus the `R`-encrypted KEK,
 *     so it restores on a brand-new device. It is never displayed. Honest copy:
 *     "keep this file safe; anyone who has it can open your vault."
 *
 * The old "set a recovery passphrase" masked entry and the base64/typed-key
 * surfaces are gone: the operator does not type or read anything.
 *
 * The plaintext-interop path ([onExportPlaintext]) still offers the otpauth://
 * list and Aegis-compatible JSON outputs (#1/#2).
 */
@Composable
fun AegisExportFlow(
    vault: UnlockedAegisVault,
    onExportPlaintext: () -> Unit,
    onDone: () -> Unit,
) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        val ctx = LocalContext.current
        val scope = rememberCoroutineScope()

        var phaseName by rememberSaveable { mutableStateOf(Phase.IDLE.name) }
        val phase = Phase.valueOf(phaseName)
        var message by remember { mutableStateOf("") }

        // SAF CreateDocument for the opaque recovery kit. The file is written by
        // [RecoveryFile.exportKit], which mints a fresh `R`, embeds it with the
        // `R`-encrypted KEK, and emits opaque bytes. Nothing here reads or shows
        // the recovery secret.
        val createKit = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("application/octet-stream"),
        ) { uri: Uri? ->
            if (uri == null) {
                phaseName = Phase.IDLE.name
                return@rememberLauncherForActivityResult
            }
            phaseName = Phase.WRITING.name
            scope.launch {
                val outcome = runCatching {
                    // KEK material is the same bytes the recovery-bundle path
                    // used; owned here and wiped after the write.
                    val kek = vault.kekMaterial()
                    try {
                        withContext(Bg.io) {
                            ctx.contentResolver.openOutputStream(uri)?.use { out ->
                                RecoveryFile.exportKit(ctx, out, kek)
                            } ?: error("Could not open the chosen file for writing.")
                        }
                    } finally {
                        Crypto.wipe(kek)
                    }
                }
                outcome.fold(
                    onSuccess = { phaseName = Phase.DONE.name; message = "Recovery file saved." },
                    onFailure = { phaseName = Phase.ERROR.name; message = it.messageForUser() },
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
                "Export recovery file",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            when (phase) {
                Phase.IDLE -> {
                    Text(
                        "This saves one recovery file for your vault. Keep it somewhere " +
                            "safe — anyone who has it can open your vault. Use it to restore " +
                            "on a new phone or after a fingerprint/lock-screen change.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    SecureButton(
                        onClick = { createKit.launch("aegis-recovery.ukit") },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Export recovery file") }
                    SecureOutlinedButton(
                        onClick = onExportPlaintext,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Export for another app (unencrypted)…") }
                    SecureOutlinedButton(
                        onClick = onDone,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Done") }
                }
                Phase.WRITING -> {
                    Text("Writing…", style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    CircularProgressIndicator()
                }
                Phase.DONE -> {
                    Text(message, style = MaterialTheme.typography.bodyMedium,
                        color = UnderstoryTheme.semantic.success)
                    Spacer(Modifier.height(4.dp))
                    SecureButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                        Text("Done")
                    }
                }
                Phase.ERROR -> {
                    Text(message, style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(4.dp))
                    SecureButton(
                        onClick = { phaseName = Phase.IDLE.name },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Try again") }
                    SecureOutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) {
                        Text("Back")
                    }
                }
            }
        }
    }
}

private enum class Phase { IDLE, WRITING, DONE, ERROR }
