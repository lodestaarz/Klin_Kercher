package com.example.klin_kercher.core.file

import com.example.klin_kercher.core.FileHashes
import java.io.InputStream
import java.security.MessageDigest

/**
 * Lê o arquivo UMA vez e, durante essa leitura:
 *  - calcula SHA-256, SHA-1 e MD5;
 *  - guarda os primeiros bytes (para descobrir o tipo real do arquivo);
 *  - procura marcadores de conteúdo perigoso (macros do Office, JavaScript em PDF, nomes internos de APK…).
 *
 * Assim um arquivo grande não precisa ser lido várias vezes.
 */
class FileScanner(
    private val markers: List<Marker> = Marker.DEFAULTS,
    private val headerSize: Int = 8192,
) {

    /** Um padrão de bytes procurado no conteúdo. */
    class Marker(val id: String, val bytes: ByteArray) {

        companion object {
            fun ascii(id: String, text: String) = Marker(id, text.toByteArray(Charsets.ISO_8859_1))
            fun utf16le(id: String, text: String) = Marker(id, text.toByteArray(Charsets.UTF_16LE))

            val DEFAULTS: List<Marker> = listOf(
                // Office antigo (doc/xls/ppt, formato OLE): fluxo "_VBA_PROJECT" gravado em UTF-16
                utf16le(VBA_PROJECT_OLE, "_VBA_PROJECT"),
                utf16le(MACROS_OLE, "Macros"),
                // PDF
                ascii(PDF_JAVASCRIPT, "/JavaScript"),
                // "/JS" seguido de um delimitador, para não confundir com bytes aleatórios
                ascii(PDF_JS, "/JS "), ascii(PDF_JS, "/JS("), ascii(PDF_JS, "/JS<"),
                ascii(PDF_JS, "/JS/"), ascii(PDF_JS, "/JS\n"), ascii(PDF_JS, "/JS\r"),
                ascii(PDF_OPENACTION, "/OpenAction"),
                ascii(PDF_LAUNCH, "/Launch"),
                ascii(PDF_EMBEDDED, "/EmbeddedFile"),
                // Páginas e imagens SVG com código
                ascii(HTML_SCRIPT, "<script"), ascii(HTML_SCRIPT, "<SCRIPT"), ascii(HTML_SCRIPT, "<Script"),
                // Teste padrão de antivírus
                ascii(EICAR, "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"),
            )
        }
    }

    data class Result(
        val hashes: FileHashes,
        val size: Long,
        /** Primeiros bytes do arquivo. */
        val header: ByteArray,
        /** Quantas vezes cada marcador apareceu (só os encontrados). */
        val markerCounts: Map<String, Int>,
        /** Nomes dos itens internos, quando o arquivo é um ZIP (APK, DOCX, JAR…). */
        val zipEntries: List<String> = emptyList(),
        /** Algum item do ZIP é protegido por senha. */
        val zipEncrypted: Boolean = false,
    ) {
        fun has(id: String) = (markerCounts[id] ?: 0) > 0
        fun count(id: String) = markerCounts[id] ?: 0
        override fun equals(other: Any?) = other is Result && other.hashes == hashes
        override fun hashCode() = hashes.hashCode()
    }

    /**
     * @param onProgress chamado com o total de bytes lidos (para barra de progresso).
     * @param isCancelled permite interromper arquivos muito grandes.
     */
    fun scan(
        input: InputStream,
        onProgress: (Long) -> Unit = {},
        isCancelled: () -> Boolean = { false },
    ): Result {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val sha1 = MessageDigest.getInstance("SHA-1")
        val md5 = MessageDigest.getInstance("MD5")
        val header = java.io.ByteArrayOutputStream(headerSize)
        val matcher = MultiPatternMatcher(markers)
        val zip = ZipEntrySniffer()
        val buf = ByteArray(64 * 1024)
        var total = 0L
        var lastReport = 0L
        while (true) {
            if (isCancelled()) throw java.util.concurrent.CancellationException("cancelado")
            val n = input.read(buf)
            if (n < 0) break
            if (n == 0) continue
            sha256.update(buf, 0, n)
            sha1.update(buf, 0, n)
            md5.update(buf, 0, n)
            if (header.size() < headerSize) header.write(buf, 0, minOf(n, headerSize - header.size()))
            matcher.feed(buf, n)
            zip.feed(buf, n)
            total += n
            if (total - lastReport >= 1_000_000) { onProgress(total); lastReport = total }
        }
        onProgress(total)
        return Result(
            hashes = FileHashes(hex(sha256.digest()), hex(sha1.digest()), hex(md5.digest())),
            size = total,
            header = header.toByteArray(),
            markerCounts = matcher.counts(),
            zipEntries = zip.names,
            zipEncrypted = zip.encrypted,
        )
    }

    companion object {
        const val VBA_PROJECT_OLE = "vba_project_ole"
        const val MACROS_OLE = "macros_ole"
        const val PDF_JAVASCRIPT = "pdf_javascript"
        const val PDF_JS = "pdf_js"
        const val PDF_OPENACTION = "pdf_openaction"
        const val PDF_LAUNCH = "pdf_launch"
        const val PDF_EMBEDDED = "pdf_embedded"
        const val HTML_SCRIPT = "html_script"
        const val EICAR = "eicar"

        private val HEX = "0123456789abcdef".toCharArray()

        fun hex(bytes: ByteArray): String {
            val out = CharArray(bytes.size * 2)
            for (i in bytes.indices) {
                val v = bytes[i].toInt() and 0xFF
                out[i * 2] = HEX[v ushr 4]
                out[i * 2 + 1] = HEX[v and 0x0F]
            }
            return String(out)
        }
    }
}

/**
 * Procura vários padrões de bytes ao mesmo tempo num fluxo lido em pedaços
 * (autômato de Aho-Corasick). Encontra padrões mesmo quando caem na divisa entre dois pedaços.
 */
internal class MultiPatternMatcher(private val markers: List<FileScanner.Marker>) {
    private val goto = ArrayList<IntArray>()
    private val fail = ArrayList<Int>()
    private val output = ArrayList<MutableList<Int>>()
    private val counts = IntArray(markers.size)
    private var state = 0

    init {
        newNode()
        for ((idx, m) in markers.withIndex()) {
            var s = 0
            for (b in m.bytes) {
                val c = b.toInt() and 0xFF
                if (goto[s][c] == -1) goto[s][c] = newNode()
                s = goto[s][c]
            }
            output[s].add(idx)
        }
        val queue = ArrayDeque<Int>()
        for (c in 0 until 256) {
            val nxt = goto[0][c]
            if (nxt == -1) goto[0][c] = 0 else { fail[nxt] = 0; queue.add(nxt) }
        }
        while (queue.isNotEmpty()) {
            val r = queue.removeFirst()
            for (c in 0 until 256) {
                val s = goto[r][c]
                if (s == -1) {
                    goto[r][c] = goto[fail[r]][c]
                } else {
                    queue.add(s)
                    fail[s] = goto[fail[r]][c]
                    output[s].addAll(output[fail[s]])
                }
            }
        }
    }

    private fun newNode(): Int {
        goto.add(IntArray(256) { -1 })
        fail.add(0)
        output.add(mutableListOf())
        return goto.size - 1
    }

    fun feed(buf: ByteArray, len: Int) {
        var s = state
        for (i in 0 until len) {
            s = goto[s][buf[i].toInt() and 0xFF]
            val out = output[s]
            if (out.isNotEmpty()) for (idx in out) if (counts[idx] < 1_000_000) counts[idx]++
        }
        state = s
    }

    fun counts(): Map<String, Int> {
        val out = HashMap<String, Int>()
        for ((i, m) in markers.withIndex()) if (counts[i] > 0) out[m.id] = (out[m.id] ?: 0) + counts[i]
        return out
    }
}

/**
 * Lê os nomes dos itens de um ZIP enquanto o arquivo passa, procurando os cabeçalhos
 * locais ("PK\u0003\u0004"). Não descompacta nada.
 */
internal class ZipEntrySniffer(private val maxEntries: Int = 5000) {
    val names = ArrayList<String>()
    var encrypted = false
        private set

    private var last4 = 0
    private val header = ByteArray(26)
    private var headerPos = -1
    private var nameBuf: ByteArray? = null
    private var namePos = 0
    private var flags = 0

    fun feed(buf: ByteArray, len: Int) {
        if (names.size >= maxEntries) return
        for (i in 0 until len) {
            val b = buf[i]
            val nb = nameBuf
            if (nb != null) {
                nb[namePos++] = b
                if (namePos == nb.size) {
                    val name = String(nb, if (flags and 0x800 != 0) Charsets.UTF_8 else Charsets.ISO_8859_1)
                    if (name.isNotEmpty() && name.all { it.code >= 32 && it != '\u007f' }) {
                        names.add(name)
                        if (flags and 1 != 0) encrypted = true
                    }
                    nameBuf = null
                }
                continue
            }
            if (headerPos >= 0) {
                header[headerPos++] = b
                if (headerPos == 26) {
                    headerPos = -1
                    flags = (header[2].toInt() and 0xFF) or ((header[3].toInt() and 0xFF) shl 8)
                    val nameLen = (header[22].toInt() and 0xFF) or ((header[23].toInt() and 0xFF) shl 8)
                    if (nameLen in 1..1024) { nameBuf = ByteArray(nameLen); namePos = 0 }
                }
                continue
            }
            last4 = (last4 shl 8) or (b.toInt() and 0xFF)
            if (last4 == 0x504B0304) { headerPos = 0; last4 = 0 }
        }
    }
}
