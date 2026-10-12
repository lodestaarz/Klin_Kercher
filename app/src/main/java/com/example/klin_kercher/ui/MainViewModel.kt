package com.example.klin_kercher.ui

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.klin_kercher.core.file.FileAnalysis
import com.example.klin_kercher.core.file.FileAnalyzer
import com.example.klin_kercher.core.importer.ListImporter
import com.example.klin_kercher.core.url.UrlAnalysis
import com.example.klin_kercher.core.url.UrlAnalyzer
import com.example.klin_kercher.core.url.UrlExtractor
import com.example.klin_kercher.data.BundledBase
import com.example.klin_kercher.data.ThreatDatabase
import com.example.klin_kercher.data.UriFiles
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class Tab { LINKS, FILES, BASE }

enum class ListKind { HASHES, DOMAINS }

data class LinkState(
    val input: String = "",
    val running: Boolean = false,
    val results: List<UrlAnalysis> = emptyList(),
    /** O texto analisado não tinha nenhum endereço reconhecível. */
    val nothingFound: Boolean = false,
)

data class FileState(
    val running: Boolean = false,
    val fileName: String? = null,
    val bytesRead: Long = 0,
    val totalBytes: Long? = null,
    val result: FileAnalysis? = null,
    val error: String? = null,
)

data class BaseState(
    val loading: Boolean = true,
    val stats: ThreatDatabase.Stats? = null,
    val busy: Boolean = false,
    val message: String? = null,
)

/**
 * Estado das três telas. Toda análise roda fora da thread principal e sem internet.
 */
class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val db = ThreatDatabase.get(app)
    private val bundled = BundledBase(app)
    private val urlAnalyzer = UrlAnalyzer(db)
    private val fileAnalyzer = FileAnalyzer(db)

    private val _tab = MutableStateFlow(Tab.LINKS)
    val tab: StateFlow<Tab> = _tab.asStateFlow()

    private val _links = MutableStateFlow(LinkState())
    val links: StateFlow<LinkState> = _links.asStateFlow()

    private val _files = MutableStateFlow(FileState())
    val files: StateFlow<FileState> = _files.asStateFlow()

    private val _base = MutableStateFlow(BaseState())
    val base: StateFlow<BaseState> = _base.asStateFlow()

    /** Completa quando a base embutida terminou de carregar (só demora na primeira abertura). */
    private val ready = CompletableDeferred<Unit>()
    private var fileJob: Job? = null

    init {
        viewModelScope.launch {
            var error: String? = null
            withContext(Dispatchers.IO) {
                try {
                    bundled.ensureLoaded(db)
                } catch (e: Exception) {
                    error = "Não foi possível carregar a base embutida: ${e.message}"
                }
            }
            ready.complete(Unit)
            refreshStats(message = error)
        }
    }

    fun selectTab(tab: Tab) {
        _tab.value = tab
    }

    // ------------------------------------------------------------------ links

    fun onLinkInputChange(text: String) {
        _links.update { it.copy(input = text, nothingFound = false) }
    }

    fun analyzeLinks() {
        val text = _links.value.input.trim()
        if (text.isEmpty()) return
        _links.update { it.copy(running = true, nothingFound = false) }
        viewModelScope.launch {
            ready.await()
            val results = withContext(Dispatchers.Default) {
                val candidates = UrlExtractor.extract(text).ifEmpty { listOf(text) }
                candidates.map { urlAnalyzer.analyze(it) }.filter { it.isRecognized }
            }
            _links.update { it.copy(running = false, results = results, nothingFound = results.isEmpty()) }
        }
    }

    fun clearLinks() {
        _links.value = LinkState()
    }

    /** Texto recebido por "Compartilhar" ou pelo menu de seleção de texto. */
    fun analyzeSharedText(text: String) {
        _tab.value = Tab.LINKS
        _links.update { it.copy(input = text.trim()) }
        analyzeLinks()
    }

    // ---------------------------------------------------------------- arquivos

    fun analyzeFile(uri: Uri) {
        _tab.value = Tab.FILES
        fileJob?.cancel()
        val resolver = getApplication<Application>().contentResolver
        fileJob = viewModelScope.launch {
            _files.value = FileState(running = true)
            try {
                val result = withContext(Dispatchers.IO) {
                    val info = UriFiles.info(resolver, uri)
                    _files.update { it.copy(fileName = info.name, totalBytes = info.size) }
                    ready.await()
                    val input = resolver.openInputStream(uri) ?: throw java.io.FileNotFoundException("sem acesso ao arquivo")
                    input.use { stream ->
                        fileAnalyzer.analyze(
                            fileName = info.name,
                            input = stream,
                            onProgress = { read -> _files.update { it.copy(bytesRead = read) } },
                            isCancelled = { !isActive },
                        )
                    }
                }
                _files.update { it.copy(running = false, result = result, bytesRead = result.size) }
            } catch (e: CancellationException) {
                _files.update { it.copy(running = false) }
                throw e
            } catch (e: SecurityException) {
                _files.update { it.copy(running = false, error = "O Android não deu permissão para ler este arquivo. Tente escolher de novo pelo botão.") }
            } catch (e: java.io.IOException) {
                _files.update { it.copy(running = false, error = "Não foi possível ler o arquivo: ${e.message ?: "erro de leitura"}") }
            } catch (e: Exception) {
                _files.update { it.copy(running = false, error = "Erro inesperado: ${e.message ?: e.javaClass.simpleName}") }
            }
        }
    }

    fun cancelFile() {
        fileJob?.cancel()
        _files.update { it.copy(running = false, error = "Análise cancelada.") }
    }

    fun clearFile() {
        fileJob?.cancel()
        _files.value = FileState()
    }

    // -------------------------------------------------------------- base local

    fun importList(uri: Uri, kind: ListKind) {
        val resolver = getApplication<Application>().contentResolver
        _base.update { it.copy(busy = true, message = null) }
        viewModelScope.launch {
            ready.await()
            val message = withContext(Dispatchers.IO) {
                try {
                    val info = UriFiles.info(resolver, uri)
                    val input = resolver.openInputStream(uri) ?: return@withContext "Não foi possível abrir ${info.name}."
                    val parsed = input.bufferedReader(Charsets.UTF_8).use { reader ->
                        when (kind) {
                            ListKind.HASHES -> ListImporter.parseHashes(reader)
                            ListKind.DOMAINS -> ListImporter.parseDomainsAndUrls(reader)
                        }
                    }
                    if (parsed.total == 0) {
                        "Nenhum item válido encontrado em ${info.name}. " +
                            if (kind == ListKind.HASHES) "A lista deve ter hashes SHA-256, SHA-1 ou MD5." else "A lista deve ter domínios ou endereços."
                    } else {
                        val added = db.insert(parsed, "importado: ${info.name}", ThreatDatabase.ORIGIN_IMPORTED)
                        val repeated = parsed.total - added
                        buildString {
                            append("${info.name}: $added ${if (added == 1) "item novo adicionado" else "itens novos adicionados"}")
                            if (repeated > 0) append(", $repeated já estavam na base")
                            if (parsed.skippedLines > 0) append(", ${parsed.skippedLines} linhas ignoradas")
                            append('.')
                        }
                    }
                } catch (e: Exception) {
                    "Falha ao importar: ${e.message ?: e.javaClass.simpleName}"
                }
            }
            refreshStats(message)
        }
    }

    fun clearImported() {
        _base.update { it.copy(busy = true, message = null) }
        viewModelScope.launch {
            withContext(Dispatchers.IO) { db.deleteByOrigin(ThreatDatabase.ORIGIN_IMPORTED) }
            refreshStats("Itens importados removidos. A base embutida foi mantida.")
        }
    }

    fun reloadBundled() {
        _base.update { it.copy(busy = true, message = null) }
        viewModelScope.launch {
            val msg = withContext(Dispatchers.IO) {
                try {
                    bundled.ensureLoaded(db, force = true)
                    "Base embutida recarregada."
                } catch (e: Exception) {
                    "Falha ao recarregar: ${e.message}"
                }
            }
            refreshStats(msg)
        }
    }

    fun dismissBaseMessage() {
        _base.update { it.copy(message = null) }
    }

    private suspend fun refreshStats(message: String? = null) {
        val stats = withContext(Dispatchers.IO) {
            try { db.stats() } catch (e: Exception) { null }
        }
        _base.update { it.copy(loading = false, busy = false, stats = stats, message = message ?: it.message) }
    }
}
