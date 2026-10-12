package com.example.klin_kercher

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.lifecycle.ViewModelProvider
import com.example.klin_kercher.ui.KlinKercherApp
import com.example.klin_kercher.ui.MainViewModel
import com.example.klin_kercher.ui.theme.Klin_KercherTheme

class MainActivity : ComponentActivity() {

    private lateinit var vm: MainViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        vm = ViewModelProvider(this)[MainViewModel::class.java]
        // Ao girar a tela a Activity é recriada; o pedido original não deve ser analisado de novo.
        if (savedInstanceState == null) handleIncoming(intent)
        setContent {
            Klin_KercherTheme {
                KlinKercherApp(vm)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncoming(intent)
    }

    /**
     * Trata o que chega de outros apps:
     *  - "Compartilhar" texto/link → aba Links
     *  - "Compartilhar" arquivo ou "Abrir com" → aba Arquivos
     *  - Menu de seleção de texto ("Verificar link") → aba Links
     */
    private fun handleIncoming(intent: Intent?) {
        if (intent == null) return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val stream = streamUri(intent)
                if (stream != null) {
                    vm.analyzeFile(stream)
                } else {
                    val text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
                        ?: intent.getStringExtra(Intent.EXTRA_SUBJECT)
                    if (!text.isNullOrBlank()) vm.analyzeSharedText(text)
                }
            }
            Intent.ACTION_PROCESS_TEXT -> {
                val text = intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
                if (!text.isNullOrBlank()) vm.analyzeSharedText(text)
            }
            Intent.ACTION_VIEW -> {
                val data = intent.data
                if (data != null && (data.scheme == "content" || data.scheme == "file")) vm.analyzeFile(data)
            }
        }
    }

    private fun streamUri(intent: Intent): Uri? {
        val extra: Uri? = if (Build.VERSION.SDK_INT >= 33) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
        }
        return extra ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
    }
}
