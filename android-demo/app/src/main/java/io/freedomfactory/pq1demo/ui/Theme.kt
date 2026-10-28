package io.freedomfactory.pq1demo.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily

object Pal {
    val bg = Color(0xFF0B0B0C)
    val surface = Color(0xFF151517)
    val surface2 = Color(0xFF1E1E21)
    val line = Color(0xFF2A2A2E)
    val text = Color(0xFFEDEDED)
    val muted = Color(0xFF8D8D93)
    val green = Color(0xFF7CF29C)
    val amber = Color(0xFFFFC15E)
    val red = Color(0xFFFF6B5E)
}

val Mono = FontFamily.Monospace

@Composable
fun Pq1Theme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Pal.text,
            onPrimary = Pal.bg,
            secondary = Pal.green,
            background = Pal.bg,
            onBackground = Pal.text,
            surface = Pal.surface,
            onSurface = Pal.text,
            surfaceVariant = Pal.surface2,
            onSurfaceVariant = Pal.muted,
            surfaceContainerLow = Pal.surface,
            surfaceContainer = Pal.surface,
            surfaceContainerHigh = Pal.surface2,
            outline = Pal.line,
            outlineVariant = Pal.line,
            error = Pal.red,
        ),
        content = content,
    )
}
