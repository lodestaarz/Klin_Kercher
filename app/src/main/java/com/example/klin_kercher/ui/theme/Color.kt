package com.example.klin_kercher.ui.theme

import androidx.compose.ui.graphics.Color

// Paleta inspirada no logo: tinta preta sobre papel, com um toque cáqui de sobretudo de detetive.
val Ink = Color(0xFF1B1B1F)
val InkSoft = Color(0xFF45464F)
val Paper = Color(0xFFF7F5F0)
val PaperDim = Color(0xFFEDEAE3)
val PaperCard = Color(0xFFFFFFFF)
val Khaki = Color(0xFF8A6A3A)
val KhakiLight = Color(0xFFD9BC8C)
val KhakiContainer = Color(0xFFF3E6CF)

val Night = Color(0xFF111113)
val NightCard = Color(0xFF1C1C1F)
val NightHigh = Color(0xFF26262A)
val Chalk = Color(0xFFEDEAE3)

/** Cores dos vereditos: cor forte (texto/ícone) e fundo suave. */
data class VerdictColors(val strong: Color, val container: Color, val onContainer: Color)

val SafeLight = VerdictColors(Color(0xFF1E6B34), Color(0xFFDCF1E0), Color(0xFF0B3A19))
val WarnLight = VerdictColors(Color(0xFF8F5300), Color(0xFFFFEBC9), Color(0xFF4A2A00))
val DangerLight = VerdictColors(Color(0xFFB3261E), Color(0xFFFCE0DD), Color(0xFF5C0E0A))

val SafeDark = VerdictColors(Color(0xFF7FD69A), Color(0xFF173A22), Color(0xFFCFF3D8))
val WarnDark = VerdictColors(Color(0xFFFFC266), Color(0xFF3F2C0D), Color(0xFFFFE4B8))
val DangerDark = VerdictColors(Color(0xFFFF8A80), Color(0xFF4A1A17), Color(0xFFFFDAD5))
