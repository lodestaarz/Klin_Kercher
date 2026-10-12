package com.example.klin_kercher.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

private val Default = Typography()

/** Tipografia: títulos com serifa (ar de "dossiê"), textos sem serifa para leitura fácil. */
val Typography = Typography(
    headlineSmall = Default.headlineSmall.copy(fontFamily = FontFamily.Serif, fontWeight = FontWeight.Bold),
    titleLarge = Default.titleLarge.copy(fontFamily = FontFamily.Serif, fontWeight = FontWeight.Bold),
    titleMedium = Default.titleMedium.copy(fontWeight = FontWeight.SemiBold),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.5.sp,
    ),
    labelSmall = Default.labelSmall.copy(fontWeight = FontWeight.Medium, letterSpacing = 0.8.sp),
)

/** Fonte de largura fixa para hashes. */
val Mono = FontFamily.Monospace
