package com.example.klin_kercher.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.example.klin_kercher.R
import com.example.klin_kercher.ui.BaseState
import com.example.klin_kercher.ui.components.HintRow
import com.example.klin_kercher.ui.components.SectionCard
import com.example.klin_kercher.ui.components.SectionTitle
import com.example.klin_kercher.ui.components.formatCount

@Composable
fun BaseScreen(
    state: BaseState,
    onImportHashes: () -> Unit,
    onImportDomains: () -> Unit,
    onClearImported: () -> Unit,
    onReloadBundled: () -> Unit,
    onDismissMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmClear by remember { mutableStateOf(false) }

    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SectionCard {
            Text("Base local", style = MaterialTheme.typography.titleLarge)
            Text(
                "Listas de ameaças guardadas neste aparelho. Os links e arquivos são comparados com elas sem enviar nada para a internet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val s = state.stats
            if (state.loading || s == null) {
                Text("Carregando a base…", style = MaterialTheme.typography.bodyMedium)
                LinearProgressIndicator(Modifier.fillMaxWidth())
            } else {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    StatBox("Hashes", s.hashes, Modifier.weight(1f))
                    StatBox("Domínios", s.domains, Modifier.weight(1f))
                    StatBox("Endereços", s.urls, Modifier.weight(1f))
                }
                Text(
                    buildString {
                        append("Embutidos no app: ${formatCount(s.total - s.imported)}")
                        s.bundledDate?.let { append(" (") ; append(it); append(")") }
                        append("\nImportados por você: ${formatCount(s.imported)}")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        }

        state.message?.let { msg ->
            SectionCard {
                HintRow(R.drawable.ic_info, msg)
                TextButton(onClick = onDismissMessage, modifier = Modifier.align(Alignment.End)) { Text("OK") }
            }
        }

        SectionCard {
            SectionTitle("Importar listas")
            Text(
                "Use arquivos de texto (.txt ou .csv) baixados no computador ou no celular.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = onImportHashes, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
                Icon(painterResource(R.drawable.ic_upload), contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Importar lista de hashes")
            }
            Button(onClick = onImportDomains, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
                Icon(painterResource(R.drawable.ic_upload), contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Importar lista de domínios ou links")
            }
            HorizontalDivider()
            Text("Formatos aceitos", style = MaterialTheme.typography.titleSmall)
            HintRow(R.drawable.ic_file, "Hashes: um SHA-256, SHA-1 ou MD5 por linha, ou CSV (como a exportação do MalwareBazaar).")
            HintRow(R.drawable.ic_link, "Domínios: um por linha, arquivo hosts (0.0.0.0 site.com), regras AdBlock (||site.com^), links completos (URLhaus, OpenPhish) ou CSV.")
            HintRow(R.drawable.ic_info, "Links em sites de arquivos compartilhados (Google Drive, GitHub…) bloqueiam só aquele endereço, não o site inteiro.")
        }

        SectionCard {
            SectionTitle("Manutenção")
            OutlinedButton(
                onClick = { confirmClear = true },
                enabled = !state.busy && (state.stats?.imported ?: 0) > 0,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(painterResource(R.drawable.ic_delete), contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Remover itens importados")
            }
            OutlinedButton(onClick = onReloadBundled, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) {
                Icon(painterResource(R.drawable.ic_refresh), contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Recarregar base embutida")
            }
        }

        SectionCard {
            HintRow(
                R.drawable.ic_verdict_safe,
                "Privacidade: o Klin Kercher não tem permissão de acesso à internet. Nada do que você verifica sai do aparelho.",
            )
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Remover itens importados?") },
            text = { Text("As listas que você importou serão apagadas. A base que vem com o app continua.") },
            confirmButton = {
                TextButton(onClick = { confirmClear = false; onClearImported() }) { Text("Remover") }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text("Cancelar") }
            },
        )
    }
}

@Composable
private fun StatBox(label: String, value: Int, modifier: Modifier = Modifier) {
    androidx.compose.material3.Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = androidx.compose.foundation.shape.RoundedCornerShape(14.dp),
    ) {
        Column(Modifier.padding(horizontal = 10.dp, vertical = 12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(formatCount(value), style = MaterialTheme.typography.titleMedium, maxLines = 1)
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
