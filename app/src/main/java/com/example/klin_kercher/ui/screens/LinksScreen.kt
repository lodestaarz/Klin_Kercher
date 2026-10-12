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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.klin_kercher.R
import com.example.klin_kercher.core.Severity
import com.example.klin_kercher.core.url.UrlAnalysis
import com.example.klin_kercher.ui.LinkState
import com.example.klin_kercher.ui.components.FindingList
import com.example.klin_kercher.ui.components.HintRow
import com.example.klin_kercher.ui.components.SectionCard
import com.example.klin_kercher.ui.components.SectionTitle
import com.example.klin_kercher.ui.components.VerdictBanner
import com.example.klin_kercher.ui.components.readClipboardText

@Composable
fun LinksScreen(
    state: LinkState,
    onInputChange: (String) -> Unit,
    onAnalyze: () -> Unit,
    onClear: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val focus = LocalFocusManager.current
    val analyze = {
        focus.clearFocus()
        onAnalyze()
    }

    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        SectionCard {
            Text("Verificar link", style = MaterialTheme.typography.titleLarge)
            Text(
                "Cole o link ou a mensagem inteira que você recebeu. A análise é feita no aparelho, sem internet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.input,
                onValueChange = onInputChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Link ou mensagem") },
                placeholder = { Text("ex.: https://exemplo.com.br/promocao") },
                minLines = 2,
                maxLines = 6,
                shape = RoundedCornerShape(14.dp),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = { analyze() }),
                trailingIcon = if (state.input.isNotEmpty()) {
                    {
                        IconButton(onClick = onClear) {
                            Icon(painterResource(R.drawable.ic_close), contentDescription = "Limpar")
                        }
                    }
                } else null,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = {
                        val text = readClipboardText(context)
                        if (!text.isNullOrBlank()) {
                            onInputChange(text)
                            analyze()
                        }
                    },
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(painterResource(R.drawable.ic_paste), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Colar e analisar")
                }
                Button(
                    onClick = analyze,
                    enabled = state.input.isNotBlank() && !state.running,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(painterResource(R.drawable.ic_search), contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Analisar")
                }
            }
            if (state.running) LinearProgressIndicator(Modifier.fillMaxWidth())
        }

        if (state.nothingFound) {
            SectionCard {
                HintRow(R.drawable.ic_info, "Não encontrei nenhum endereço de site nesse texto. Confira se copiou o link inteiro.")
            }
        }

        if (state.results.size > 1) {
            Text(
                "${state.results.size} links encontrados na mensagem",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 4.dp),
            )
        }
        for (r in state.results) UrlResultCard(r)

        if (state.results.isEmpty() && !state.running && !state.nothingFound) {
            SectionCard {
                SectionTitle("Como usar")
                HintRow(R.drawable.ic_link, "No WhatsApp, SMS ou e-mail: segure a mensagem, toque em Compartilhar e escolha \"Verificar com Klin Kercher\".")
                HintRow(R.drawable.ic_search, "Ou selecione o link em qualquer app e toque em \"Verificar link\" no menu.")
                HintRow(R.drawable.ic_info, "Quer testar? Analise https://login.golpe-exemplo.test — um endereço fictício que está na base local.")
            }
        }
    }
}

@Composable
private fun UrlResultCard(result: UrlAnalysis, nested: Boolean = false) {
    SectionCard {
        VerdictBanner(result.verdict, compact = nested)

        val p = result.parsed
        Column {
            Text(
                if (nested) "Site de destino" else "Site analisado",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                p?.unicodeHost ?: result.input,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            if (p != null) {
                Text(
                    p.display(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        result.officialBrand?.let { brand ->
            Surface(
                color = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                shape = RoundedCornerShape(50),
            ) {
                Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(painterResource(R.drawable.ic_verdict_safe), contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Domínio oficial de $brand", style = MaterialTheme.typography.labelLarge)
                }
            }
        }

        val shown = result.findings.filter { it.code != "REDIRECT" && it.code != "OFFICIAL_DOMAIN" }
        if (shown.isNotEmpty()) {
            HorizontalDivider()
            FindingList(shown)
        } else if (result.redirect == null) {
            Text(
                "Nenhum sinal suspeito no endereço.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        result.redirect?.let { target ->
            HorizontalDivider()
            SectionTitle("Para onde este link leva")
            if (target.verdict.ordinal > ownVerdictOrdinal(result)) {
                Text(
                    "O veredito acima considera o site de destino.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            UrlResultCard(target, nested = true)
        }
    }
}

private fun ownVerdictOrdinal(r: UrlAnalysis): Int =
    com.example.klin_kercher.core.Verdict.from(r.findings.filter { it.severity != Severity.INFO }).ordinal
