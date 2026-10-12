package com.example.klin_kercher.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

private val LightColors = lightColorScheme(
    primary = Ink,
    onPrimary = Color.White,
    primaryContainer = PaperDim,
    onPrimaryContainer = Ink,
    secondary = Khaki,
    onSecondary = Color.White,
    secondaryContainer = KhakiContainer,
    onSecondaryContainer = Color(0xFF3A2A10),
    tertiary = Khaki,
    background = Paper,
    onBackground = Ink,
    surface = Paper,
    onSurface = Ink,
    surfaceVariant = PaperDim,
    onSurfaceVariant = InkSoft,
    surfaceContainerLowest = PaperCard,
    surfaceContainerLow = PaperCard,
    surfaceContainer = Color(0xFFF1EEE7),
    surfaceContainerHigh = PaperDim,
    surfaceContainerHighest = Color(0xFFE5E1D8),
    outline = Color(0xFF8A8780),
    outlineVariant = Color(0xFFD6D2C8),
)

private val DarkColors = darkColorScheme(
    primary = Chalk,
    onPrimary = Ink,
    primaryContainer = NightHigh,
    onPrimaryContainer = Chalk,
    secondary = KhakiLight,
    onSecondary = Color(0xFF3A2A10),
    secondaryContainer = Color(0xFF4A3818),
    onSecondaryContainer = KhakiContainer,
    tertiary = KhakiLight,
    background = Night,
    onBackground = Chalk,
    surface = Night,
    onSurface = Chalk,
    surfaceVariant = NightHigh,
    onSurfaceVariant = Color(0xFFC7C5BE),
    surfaceContainerLowest = Color(0xFF0C0C0E),
    surfaceContainerLow = NightCard,
    surfaceContainer = NightCard,
    surfaceContainerHigh = NightHigh,
    surfaceContainerHighest = Color(0xFF303035),
    outline = Color(0xFF908E88),
    outlineVariant = Color(0xFF3F3F44),
)

@Immutable
data class KlinColors(val safe: VerdictColors, val warn: VerdictColors, val danger: VerdictColors)

val LocalKlinColors = staticCompositionLocalOf { KlinColors(SafeLight, WarnLight, DangerLight) }

/**
 * Tema do app. As cores dinâmicas do Android 12 foram desligadas de propósito:
 * o preto e branco do logo e as cores dos vereditos precisam ser sempre as mesmas.
 */
@Composable
fun Klin_KercherTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val klin = if (darkTheme) KlinColors(SafeDark, WarnDark, DangerDark) else KlinColors(SafeLight, WarnLight, DangerLight)
    CompositionLocalProvider(LocalKlinColors provides klin) {
        MaterialTheme(
            colorScheme = if (darkTheme) DarkColors else LightColors,
            typography = Typography,
            content = content,
        )
    }
}
