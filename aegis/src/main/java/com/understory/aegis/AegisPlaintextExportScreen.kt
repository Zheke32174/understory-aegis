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
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.messageForUser
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Plaintext / incumbent-interop export (design §3.1 outputs #1 and #2). NEW
 * screen, token-native. Reached only behind the shared export screen's
 * second, destructive-styled confirmation, so the user has already acknowledged
 * that these formats write secrets UNENCRYPTED to a file they choose.
 *
 * Two outputs, each via SAF `CreateDocument` (no storage permission):
 *   1. otpauth:// URI list (.txt) — one URI per entry, round-trips through our
 *      own importer and any standard authenticator.
 *   2. Aegis Authenticator-compatible JSON (.json) — importable by the
 *      operator's real Aegis Authenticator.
 *
 * Serialization runs off-main on [Bg.cpu]; the SAF write on [Bg.io].
 */
@Composable
fun AegisPlaintextExportScreen(
    vault: UnlockedAegisVault,
    onDone: () -> Unit,
) {
    UnderstoryTheme(accent = UnderstoryAccent.AEGIS) {
        val ctx = LocalContext.current
        val scope = rememberCoroutineScope()

        // Only the opaque phase name survives config change.
        var phaseName by rememberSaveable { mutableStateOf(Phase.IDLE.name) }
        val phase = Phase.valueOf(phaseName)
        var message by remember { mutableStateOf("") }
        // Which format the pending SAF create is for (opaque, survives config).
        var pendingFormat by rememberSaveable { mutableStateOf("") }

        fun writeSelected(uri: Uri) {
            phaseName = Phase.WRITING.name
            val fmt = pendingFormat
            scope.launch {
                val outcome = runCatching {
                    val text = withContext(Bg.cpu) {
                        when (fmt) {
                            FORMAT_URIS -> AegisAuthExport.toOtpAuthUriList(vault.contents.entries)
                            else -> AegisAuthExport.toAegisJson(vault.contents.entries)
                        }
                    }
                    withContext(Bg.io) {
                        ctx.contentResolver.openOutputStream(uri)?.use { out ->
                            out.write(text.toByteArray(Charsets.UTF_8))
                        } ?: error("Could not open the chosen file for writing.")
                    }
                }
                outcome.fold(
                    onSuccess = { phaseName = Phase.DONE.name; message = "Export written." },
                    onFailure = { phaseName = Phase.ERROR.name; message = it.messageForUser() },
                )
            }
        }

        val createUris = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("text/plain"),
        ) { uri: Uri? ->
            if (uri == null) { phaseName = Phase.IDLE.name } else writeSelected(uri)
        }
        val createJson = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("application/json"),
        ) { uri: Uri? ->
            if (uri == null) { phaseName = Phase.IDLE.name } else writeSelected(uri)
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                "Export for another app (unencrypted)",
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            when (phase) {
                Phase.IDLE -> {
                    Text(
                        "These write your TOTP/HOTP secrets in PLAINTEXT to a file you " +
                            "choose. Anyone with the file can generate your codes. Use only " +
                            "to hand your seeds to another authenticator.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = UnderstoryTheme.semantic.warning,
                    )
                    Spacer(Modifier.height(4.dp))
                    SecureButton(
                        onClick = {
                            pendingFormat = FORMAT_URIS
                            createUris.launch("understory-otp-uris.txt")
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Save otpauth:// URI list (.txt)") }
                    SecureButton(
                        onClick = {
                            pendingFormat = FORMAT_JSON
                            createJson.launch("understory-otp-aegis.json")
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Save Aegis Authenticator JSON (.json)") }
                    SecureOutlinedButton(
                        onClick = onDone,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Back") }
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

private const val FORMAT_URIS = "uris"
private const val FORMAT_JSON = "json"
private enum class Phase { IDLE, WRITING, DONE, ERROR }
