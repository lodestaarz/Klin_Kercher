package com.example.klin_kercher.core.file

/** Grupo de tipos de arquivo, usado para comparar o que o nome promete com o que o arquivo é. */
enum class FileCategory(val label: String) {
    EXECUTABLE("programa ou aplicativo"),
    DOCUMENT("documento"),
    IMAGE("imagem"),
    MEDIA("áudio ou vídeo"),
    ARCHIVE("arquivo compactado"),
    WEB("página da web"),
    UNKNOWN("desconhecido"),
}

/** Tipo real do arquivo, descoberto pelo conteúdo (assinatura nos primeiros bytes). */
enum class RealType(val label: String, val category: FileCategory) {
    APK("Aplicativo Android (APK)", FileCategory.EXECUTABLE),
    DEX("Código de aplicativo Android (DEX)", FileCategory.EXECUTABLE),
    JAR("Programa Java (JAR)", FileCategory.EXECUTABLE),
    PE_EXE("Programa do Windows (EXE/DLL)", FileCategory.EXECUTABLE),
    ELF("Programa Linux/Android nativo (ELF)", FileCategory.EXECUTABLE),
    MACHO("Programa do macOS/iOS", FileCategory.EXECUTABLE),
    SCRIPT("Script executável", FileCategory.EXECUTABLE),
    LNK("Atalho do Windows (LNK)", FileCategory.EXECUTABLE),
    PDF("Documento PDF", FileCategory.DOCUMENT),
    OOXML("Documento do Office (docx/xlsx/pptx)", FileCategory.DOCUMENT),
    OLE("Documento do Office antigo (doc/xls/ppt)", FileCategory.DOCUMENT),
    ODF("Documento OpenDocument", FileCategory.DOCUMENT),
    RTF("Documento RTF", FileCategory.DOCUMENT),
    TEXT("Texto", FileCategory.DOCUMENT),
    HTML("Página da web (HTML)", FileCategory.WEB),
    SVG("Imagem SVG", FileCategory.WEB),
    PNG("Imagem PNG", FileCategory.IMAGE),
    JPEG("Imagem JPEG", FileCategory.IMAGE),
    GIF("Imagem GIF", FileCategory.IMAGE),
    WEBP("Imagem WebP", FileCategory.IMAGE),
    BMP("Imagem BMP", FileCategory.IMAGE),
    HEIF("Imagem HEIC/HEIF", FileCategory.IMAGE),
    MP4("Vídeo MP4/MOV", FileCategory.MEDIA),
    MP3("Áudio MP3", FileCategory.MEDIA),
    OGG("Áudio OGG/Opus", FileCategory.MEDIA),
    WAV("Áudio WAV", FileCategory.MEDIA),
    MKV("Vídeo MKV/WebM", FileCategory.MEDIA),
    ZIP("Arquivo ZIP", FileCategory.ARCHIVE),
    RAR("Arquivo RAR", FileCategory.ARCHIVE),
    SEVEN_ZIP("Arquivo 7-Zip", FileCategory.ARCHIVE),
    GZIP("Arquivo GZIP", FileCategory.ARCHIVE),
    EMPTY("Arquivo vazio", FileCategory.UNKNOWN),
    UNKNOWN("Tipo não identificado", FileCategory.UNKNOWN),
}

object FileTypeDetector {

    /** Extensão → categoria que o nome do arquivo promete. */
    val EXTENSION_CATEGORY: Map<String, FileCategory> = buildMap {
        listOf("pdf", "doc", "docx", "docm", "dot", "dotx", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "pps", "ppsx",
            "odt", "ods", "odp", "rtf", "txt", "csv", "xml", "json", "md", "epub")
            .forEach { put(it, FileCategory.DOCUMENT) }
        listOf("jpg", "jpeg", "png", "gif", "webp", "bmp", "heic", "heif", "tif", "tiff", "ico")
            .forEach { put(it, FileCategory.IMAGE) }
        listOf("mp3", "mp4", "m4a", "m4v", "wav", "ogg", "opus", "oga", "mov", "avi", "mkv", "webm", "3gp", "aac", "flac", "wmv")
            .forEach { put(it, FileCategory.MEDIA) }
        listOf("zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "iso", "img")
            .forEach { put(it, FileCategory.ARCHIVE) }
        listOf("apk", "xapk", "apks", "aab", "dex", "exe", "scr", "msi", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
            "wsf", "wsh", "hta", "jar", "ps1", "lnk", "dll", "cpl", "sh", "bin", "elf", "so", "msix", "appx", "app", "dmg", "pkg", "reg")
            .forEach { put(it, FileCategory.EXECUTABLE) }
        listOf("html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml")
            .forEach { put(it, FileCategory.WEB) }
    }

    fun extensionOf(fileName: String): String {
        val clean = fileName.trim().trimEnd('.', ' ')
        val dot = clean.lastIndexOf('.')
        if (dot <= 0 || dot == clean.length - 1) return ""
        return clean.substring(dot + 1).lowercase()
    }

    fun detect(header: ByteArray, zipEntries: List<String>): RealType {
        val h = header
        if (h.isEmpty()) return RealType.EMPTY
        fun startsWith(vararg bytes: Int, offset: Int = 0): Boolean {
            if (h.size < offset + bytes.size) return false
            for (i in bytes.indices) if ((h[offset + i].toInt() and 0xFF) != bytes[i]) return false
            return true
        }
        fun ascii(from: Int, len: Int): String =
            if (h.size < from + len) "" else String(h, from, len, Charsets.ISO_8859_1)

        // ZIP e derivados (APK, JAR, Office, OpenDocument)
        if (startsWith(0x50, 0x4B, 0x03, 0x04) || startsWith(0x50, 0x4B, 0x05, 0x06)) {
            val names = zipEntries.toSet()
            return when {
                "AndroidManifest.xml" in names && names.any { it.startsWith("classes") && it.endsWith(".dex") } -> RealType.APK
                "AndroidManifest.xml" in names -> RealType.APK
                "[Content_Types].xml" in names || names.any { it.startsWith("word/") || it.startsWith("xl/") || it.startsWith("ppt/") } -> RealType.OOXML
                "mimetype" in names && ascii(30, 8) == "mimetype" -> RealType.ODF
                "META-INF/MANIFEST.MF" in names && names.any { it.endsWith(".class") } -> RealType.JAR
                else -> RealType.ZIP
            }
        }
        if (startsWith(0x25, 0x50, 0x44, 0x46)) return RealType.PDF // %PDF
        // alguns PDFs têm lixo antes do cabeçalho; leitores aceitam até 1024 bytes
        if (indexOf(h, "%PDF-".toByteArray(), 1024) >= 0) return RealType.PDF
        if (startsWith(0x4D, 0x5A)) return RealType.PE_EXE // MZ
        if (startsWith(0x7F, 0x45, 0x4C, 0x46)) return RealType.ELF
        if (startsWith(0x64, 0x65, 0x78, 0x0A)) return RealType.DEX // dex\n
        if (startsWith(0xFE, 0xED, 0xFA, 0xCE) || startsWith(0xFE, 0xED, 0xFA, 0xCF) ||
            startsWith(0xCE, 0xFA, 0xED, 0xFE) || startsWith(0xCF, 0xFA, 0xED, 0xFE)
        ) return RealType.MACHO
        if (startsWith(0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)) return RealType.OLE
        if (startsWith(0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00)) return RealType.LNK
        if (startsWith(0x89, 0x50, 0x4E, 0x47)) return RealType.PNG
        if (startsWith(0xFF, 0xD8, 0xFF)) return RealType.JPEG
        if (ascii(0, 4) == "GIF8") return RealType.GIF
        if (ascii(0, 4) == "RIFF" && ascii(8, 4) == "WEBP") return RealType.WEBP
        if (ascii(0, 4) == "RIFF" && ascii(8, 4) == "WAVE") return RealType.WAV
        if (ascii(0, 2) == "BM" && h.size > 14 && h[6].toInt() == 0 && h[7].toInt() == 0) return RealType.BMP
        if (ascii(4, 4) == "ftyp") {
            val brand = ascii(8, 4)
            return if (brand.startsWith("hei") || brand.startsWith("mif1") || brand == "heix" || brand == "avif") RealType.HEIF else RealType.MP4
        }
        if (ascii(0, 3) == "ID3" || startsWith(0xFF, 0xFB) || startsWith(0xFF, 0xF3) || startsWith(0xFF, 0xF2)) return RealType.MP3
        if (ascii(0, 4) == "OggS") return RealType.OGG
        if (startsWith(0x1A, 0x45, 0xDF, 0xA3)) return RealType.MKV
        if (ascii(0, 6) == "Rar!\u001A\u0007") return RealType.RAR
        if (startsWith(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C)) return RealType.SEVEN_ZIP
        if (startsWith(0x1F, 0x8B)) return RealType.GZIP
        if (ascii(0, 5) == "{\\rtf") return RealType.RTF
        if (ascii(0, 2) == "#!") return RealType.SCRIPT

        // Texto: decide entre HTML, SVG e texto comum
        if (looksLikeText(h)) {
            val start = String(h, 0, minOf(h.size, 1024), Charsets.ISO_8859_1).trimStart('\uFEFF', 'ï', '»', '¿', ' ', '\n', '\r', '\t').lowercase()
            return when {
                start.startsWith("<!doctype html") || start.startsWith("<html") || start.contains("<html") || start.startsWith("<head") || start.startsWith("<script") -> RealType.HTML
                start.contains("<svg") -> RealType.SVG
                else -> RealType.TEXT
            }
        }
        return RealType.UNKNOWN
    }

    private fun looksLikeText(h: ByteArray): Boolean {
        val n = minOf(h.size, 4096)
        if (n == 0) return false
        var bad = 0
        for (i in 0 until n) {
            val b = h[i].toInt() and 0xFF
            if (b == 0) return false
            if (b < 9 || (b in 14..31)) bad++
        }
        return bad * 100 / n < 2
    }

    private fun indexOf(h: ByteArray, needle: ByteArray, limit: Int): Int {
        val max = minOf(h.size - needle.size, limit)
        outer@ for (i in 0..max) {
            for (j in needle.indices) if (h[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }
}
