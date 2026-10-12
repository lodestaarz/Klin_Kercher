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
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.klin_kercher.R
import com.example.klin_kercher.core.file.FileAnalysis
import com.example.klin_kercher.ui.FileState
import com.example.klin_kercher.ui.components.FindingList
import com.example.klin_kercher.ui.components.HintRow
import com.example.klin_kercher.ui.components.InfoRow
import com.example.klin_kercher.ui.components.SectionCard
import com.example.klin_kercher.ui.components.SectionTitle
import com.example.klin_kercher.ui.components.VerdictBanner
import com.example.klin_kercher.ui.components.copyToClipboard
import com.example.klin_kercher.ui.components.formatBytes
import com.example.klin_kercher.ui.components.formatCount

@Composable
fun FilesScreen(
    state: FileState,
    knownHashes: Int?,
    onPick: () -> Unit,
    onCancel: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SectionCard {
            Text("Verificar arquivo", style = MaterialTheme.typography.titleLarge)
            Text(
                "O app calcula a impressão digital (hash) do arquivo e compara com a base local de ameaças. " +
                    "Também confere se o arquivo é um programa disfarçado, tem macros ou código escondido.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = onPick, enabled = !state.running, modifier = Modifier.fillMaxWidth()) {
                Icon(painterResource(R.drawable.ic_folder_open), contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(if (state.result == null) "Escolher arquivo" else "Escolher outro arquivo")
            }
            if (knownHashes != null) {
                Text(
                    "Base local: ${formatCount(knownHashes)} ${if (knownHashes == 1) "hash conhecido" else "hashes conhecidos"}.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (state.running) {
            SectionCard {
                Text(
                    state.fileName?.let { "Lendo $it…" } ?: "Abrindo arquivo…",
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                val total = state.totalBytes
                if (total != null && total > 0) {
                    val fraction = (state.bytesRead.toFloat() / total).coerceIn(0f, 1f)
                    LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
                    Text(
                        "${formatBytes(state.bytesRead)} de ${formatBytes(total)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
                TextButton(onClick = onCancel) { Text("Cancelar") }
            }
        }

        state.error?.let { msg ->
            SectionCard {
                HintRow(R.drawable.ic_info, msg)
            }
        }

        state.result?.let { FileResult(it, onClear) }

        if (state.result == null && !state.running && state.error == null) {
            SectionCard {
                SectionTitle("Dicas")
                HintRow(R.drawable.ic_file, "Recebeu um anexo? Toque em Compartilhar no WhatsApp ou no e-mail e escolha \"Verificar com Klin Kercher\".")
                HintRow(R.drawable.ic_verdict_warning, "Desconfie de \"boleto.pdf.apk\", \"comprovante.zip\" com senha e documentos que pedem para habilitar macros.")
                HintRow(R.drawable.ic_info, "A verificação por hash só reconhece arquivos que já estão na base. Um resultado verde não garante que o arquivo é seguro.")
            }
        }
    }
}

@Composable
private fun FileResult(a: FileAnalysis, onClear: () -> Unit) {
    val context = LocalContext.current
    SectionCard {
        VerdictBanner(a.verdict)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            InfoRow("Arquivo", a.fileName)
            Row {
                Column(Modifier.weight(1f)) { InfoRow("Tamanho", formatBytes(a.size)) }
                Column(Modifier.weight(1f)) { InfoRow("Tipo real", a.realType.label) }
            }
            if (a.innerEntries > 0) InfoRow("Itens internos", formatCount(a.innerEntries))
        }

        if (a.findings.isNotEmpty()) {
            HorizontalDivider()
            FindingList(a.findings)
        } else {
            Text(
                "Nenhum sinal suspeito e o hash não está na base local.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        HorizontalDivider()
        SectionTitle("Impressões digitais (hash)")
        Text(
            "Você pode pesquisar estes códigos em sites como o VirusTotal, pelo navegador, para ver se outros antivírus já conhecem o arquivo.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        InfoRow("SHA-256", a.hashes.sha256, mono = true) { copyToClipboard(context, "SHA-256", a.hashes.sha256) }
        InfoRow("SHA-1", a.hashes.sha1, mono = true) { copyToClipboard(context, "SHA-1", a.hashes.sha1) }
        InfoRow("MD5", a.hashes.md5, mono = true) { copyToClipboard(context, "MD5", a.hashes.md5) }
        TextButton(onClick = onClear) { Text("Limpar resultado") }
    }
}
