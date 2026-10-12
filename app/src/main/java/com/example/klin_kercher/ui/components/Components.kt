package com.example.klin_kercher.ui.components

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.annotation.DrawableRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.klin_kercher.R
import com.example.klin_kercher.core.Finding
import com.example.klin_kercher.core.Severity
import com.example.klin_kercher.core.Verdict
import com.example.klin_kercher.ui.theme.LocalKlinColors
import com.example.klin_kercher.ui.theme.Mono
import com.example.klin_kercher.ui.theme.VerdictColors
import java.util.Locale

private val PT_BR: Locale = Locale.forLanguageTag("pt-BR")

@Composable
fun verdictColors(verdict: Verdict): VerdictColors {
    val k = LocalKlinColors.current
    return when (verdict) {
        Verdict.SEM_SINAIS -> k.safe
        Verdict.SUSPEITO -> k.warn
        Verdict.PERIGOSO -> k.danger
    }
}

@DrawableRes
fun verdictIcon(verdict: Verdict): Int = when (verdict) {
    Verdict.SEM_SINAIS -> R.drawable.ic_verdict_safe
    Verdict.SUSPEITO -> R.drawable.ic_verdict_warning
    Verdict.PERIGOSO -> R.drawable.ic_verdict_danger
}

/** Faixa colorida com o veredito: verde, amarelo ou vermelho. */
@Composable
fun VerdictBanner(verdict: Verdict, modifier: Modifier = Modifier, compact: Boolean = false) {
    val c = verdictColors(verdict)
    Surface(color = c.container, contentColor = c.onContainer, shape = RoundedCornerShape(if (compact) 14.dp else 20.dp), modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = if (compact) 10.dp else 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                painter = painterResource(verdictIcon(verdict)),
                contentDescription = null,
                tint = c.strong,
                modifier = Modifier.size(if (compact) 28.dp else 40.dp),
            )
            Spacer(Modifier.width(14.dp))
            Column {
                Text(
                    verdict.label,
                    style = if (compact) MaterialTheme.typography.titleMedium else MaterialTheme.typography.titleLarge,
                    color = c.onContainer,
                )
                if (!compact) {
                    Text(verdict.summary, style = MaterialTheme.typography.bodyMedium, color = c.onContainer)
                }
            }
        }
    }
}

@Composable
private fun severityColor(s: Severity): Color {
    val k = LocalKlinColors.current
    return when (s) {
        Severity.CRITICO, Severity.ALTO -> k.danger.strong
        Severity.MEDIO, Severity.BAIXO -> k.warn.strong
        Severity.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
    }
}

/** Lista de sinais encontrados, do mais grave ao menos grave. */
@Composable
fun FindingList(findings: List<Finding>, modifier: Modifier = Modifier) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        for (f in findings) FindingItem(f)
    }
}

@Composable
fun FindingItem(f: Finding) {
    val color = severityColor(f.severity)
    Row(Modifier.fillMaxWidth()) {
        Box(
            Modifier
                .padding(top = 6.dp)
                .size(10.dp)
                .background(color, CircleShape)
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                f.severity.label.uppercase(PT_BR),
                style = MaterialTheme.typography.labelSmall,
                color = color,
            )
            Text(f.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(f.detail, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Cartão branco padrão das telas. */
@Composable
fun SectionCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        border = CardDefaults.outlinedCardBorder(),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp), content = content)
    }
}

@Composable
fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(text, style = MaterialTheme.typography.titleMedium, modifier = modifier)
}

/** Linha "rótulo: valor", com botão de copiar opcional. */
@Composable
fun InfoRow(label: String, value: String, mono: Boolean = false, onCopy: (() -> Unit)? = null) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                value,
                style = if (mono) MaterialTheme.typography.bodySmall.copy(fontFamily = Mono) else MaterialTheme.typography.bodyMedium,
            )
        }
        if (onCopy != null) {
            IconButton(onClick = onCopy) {
                Icon(painterResource(R.drawable.ic_copy), contentDescription = "Copiar $label", modifier = Modifier.size(20.dp))
            }
        }
    }
}

/** Dica discreta com ícone. */
@Composable
fun HintRow(@DrawableRes icon: Int, text: String, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        Icon(
            painterResource(icon), contentDescription = null,
            tint = MaterialTheme.colorScheme.secondary,
            modifier = Modifier.size(20.dp).padding(top = 2.dp),
        )
        Spacer(Modifier.width(10.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

fun formatBytes(n: Long): String {
    if (n < 1024) return "$n bytes"
    val units = listOf("KB", "MB", "GB")
    var v = n.toDouble()
    var i = -1
    while (v >= 1024 && i < units.size - 1) { v /= 1024; i++ }
    return String.format(PT_BR, "%.1f %s", v, units[i])
}

fun formatCount(n: Int): String = String.format(PT_BR, "%,d", n)

fun copyToClipboard(context: Context, label: String, text: String) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    cm.setPrimaryClip(ClipData.newPlainText(label, text))
    // Android 13+ já mostra um aviso próprio ao copiar
    if (android.os.Build.VERSION.SDK_INT < 33) Toast.makeText(context, "$label copiado", Toast.LENGTH_SHORT).show()
}

fun readClipboardText(context: Context): String? {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return null
    val clip = cm.primaryClip ?: return null
    if (clip.itemCount == 0) return null
    return clip.getItemAt(0).coerceToText(context)?.toString()
}
