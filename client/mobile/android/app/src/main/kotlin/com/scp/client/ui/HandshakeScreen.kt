package com.scp.client.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Proximity Handshake screen (SCP-PHX).
 * Identity exchange occurs through physical proximity — no usernames, no directories.
 * Phase 3 deliverable.
 */
@Composable
fun HandshakeScreen(onComplete: () -> Unit = {}) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("Begin Handshake", style = MaterialTheme.typography.headlineMedium)
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            "Bring devices together to establish a corridor.\nNo usernames. No directories.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(32.dp))
        // TODO Phase 3: Bluetooth LE beacon + SCP-PHX flow
        CircularProgressIndicator()
        Spacer(modifier = Modifier.height(16.dp))
        TextButton(onClick = onComplete) { Text("Cancel") }
    }
}
