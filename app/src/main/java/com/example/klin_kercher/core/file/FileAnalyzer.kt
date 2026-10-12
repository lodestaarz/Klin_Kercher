package com.example.klin_kercher.core.file

import com.example.klin_kercher.core.FileHashes
import com.example.klin_kercher.core.Finding
import com.example.klin_kercher.core.InMemoryThreatLookup
import com.example.klin_kercher.core.Severity
import com.example.klin_kercher.core.ThreatLookup
import com.example.klin_kercher.core.Verdict
import java.io.InputStream

data class FileAnalysis(
    val fileName: String,
    val size: Long,
    val hashes: FileHashes,
    val realType: RealType,
    val extension: String,
    val findings: List<Finding>,
    val verdict: Verdict,
    /** Quantidade de itens internos, quando é um ZIP/APK/Office. */
    val innerEntries: Int,
)

/**
 * Verifica um arquivo no aparelho: compara os hashes com a base local e procura sinais
 * de arquivo perigoso. Não é um antivírus completo — não executa nem descompacta o arquivo.
 */
class FileAnalyzer(
    private val lookup: ThreatLookup = InMemoryThreatLookup.EMPTY,
    private val scanner: FileScanner = FileScanner(),
) {

    fun analyze(
        fileName: String,
        input: InputStream,
        onProgress: (Long) -> Unit = {},
        isCancelled: () -> Boolean = { false },
    ): FileAnalysis {
        val scan = scanner.scan(input, onProgress, isCancelled)
        return evaluate(fileName, scan)
    }

    fun evaluate(fileName: String, scan: FileScanner.Result): FileAnalysis {
        val findings = mutableListOf<Finding>()
        val realType = FileTypeDetector.detect(scan.header, scan.zipEntries)
        val ext = FileTypeDetector.extensionOf(fileName)
        val claimed = FileTypeDetector.EXTENSION_CATEGORY[ext]

        // 1) Base local de hashes
        val match = lookup.matchHash(scan.hashes)
        if (match != null) {
            val label = match.label?.takeIf { it.isNotBlank() }?.let { " Identificado como: $it." } ?: ""
            val src = match.source?.let { " Fonte: $it." } ?: ""
            findings += Finding(
                "HASH_MATCH", Severity.CRITICO,
                "Arquivo conhecido como malicioso",
                "A impressão digital (hash) deste arquivo está na base local de ameaças.$label$src",
            )
        }
        if (scan.has(FileScanner.EICAR) && match == null) {
            findings += Finding(
                "EICAR", Severity.CRITICO,
                "Arquivo de teste de antivírus (EICAR)",
                "Este arquivo contém a assinatura de teste EICAR. Ele é inofensivo, mas todo antivírus deve acusá-lo.",
            )
        }

        // 2) Nome do arquivo
        nameChecks(fileName, findings)

        // 3) Nome x conteúdo
        if (claimed != null && realType.category != FileCategory.UNKNOWN && claimed != realType.category) {
            val isOfficeZip = realType == RealType.OOXML && claimed == FileCategory.ARCHIVE
            val textAsDoc = realType == RealType.TEXT && claimed == FileCategory.DOCUMENT
            when {
                realType.category == FileCategory.EXECUTABLE -> findings += Finding(
                    "DISGUISED_EXECUTABLE", Severity.ALTO,
                    "Programa disfarçado de .$ext",
                    "O nome diz que é ${claimed.label} (.$ext), mas o conteúdo é: ${realType.label}. " +
                        "Esse disfarce é típico de vírus. Não abra nem instale.",
                )
                realType.category == FileCategory.WEB && claimed == FileCategory.DOCUMENT -> findings += Finding(
                    "DISGUISED_HTML", Severity.MEDIO,
                    "Não é um .$ext: é uma página da web",
                    "Páginas salvas como anexo são usadas para imitar telas de login de bancos e e-mail. " +
                        "Não digite senhas se ela abrir.",
                )
                claimed == FileCategory.EXECUTABLE && realType.category != FileCategory.EXECUTABLE -> Unit
                isOfficeZip || textAsDoc -> Unit
                else -> findings += Finding(
                    "TYPE_MISMATCH", Severity.BAIXO,
                    "Extensão não corresponde ao conteúdo",
                    "O nome indica ${claimed.label} (.$ext), mas o arquivo é: ${realType.label}.",
                )
            }
        }

        // 4) Tipos que merecem atenção por si só
        val disguised = findings.any { it.code == "DISGUISED_EXECUTABLE" }
        if (!disguised) when (realType) {
            RealType.APK -> findings += Finding(
                "APK", Severity.MEDIO,
                "Instalador de aplicativo (APK)",
                "Só instale se você mesmo baixou de uma fonte confiável. Bancos, lojas e órgãos do governo " +
                    "nunca mandam aplicativo por mensagem ou e-mail.",
            )
            RealType.PE_EXE, RealType.MACHO -> findings += Finding(
                "DESKTOP_EXECUTABLE", Severity.MEDIO,
                "Programa de computador",
                "${realType.label}. Não funciona no celular; se veio por mensagem, não repasse nem abra no computador.",
            )
            RealType.DEX, RealType.ELF, RealType.SCRIPT, RealType.JAR -> findings += Finding(
                "EXECUTABLE_CODE", Severity.MEDIO,
                "Contém código executável",
                "${realType.label}. Arquivos assim podem executar ações no aparelho.",
            )
            RealType.LNK -> findings += Finding(
                "LNK", Severity.ALTO,
                "Atalho do Windows",
                "Atalhos (.lnk) recebidos por e-mail ou mensagem são usados para executar comandos escondidos.",
            )
            else -> Unit
        }

        // 5) Macros do Office
        val ooxmlMacro = scan.zipEntries.any { it.endsWith("vbaProject.bin", ignoreCase = true) }
        val xlmMacro = scan.zipEntries.any { it.startsWith("xl/macrosheets/") }
        val oleMacro = realType == RealType.OLE && (scan.has(FileScanner.VBA_PROJECT_OLE) || scan.has(FileScanner.MACROS_OLE))
        if (ooxmlMacro || xlmMacro || oleMacro) {
            val macroFreeExt = ext in setOf("docx", "xlsx", "pptx", "dotx", "ppsx")
            findings += Finding(
                "OFFICE_MACRO", if (macroFreeExt || xlmMacro) Severity.ALTO else Severity.MEDIO,
                if (xlmMacro) "Planilha com macros antigas (Excel 4.0)" else "Documento com macros",
                (if (macroFreeExt) "Arquivos .$ext não deveriam ter macros, mas este tem. " else "") +
                    "Macros podem instalar vírus. Se abrir, NÃO clique em \"Habilitar conteúdo\" ou \"Habilitar macros\".",
            )
        }

        // 6) PDF
        if (realType == RealType.PDF) {
            val hasJs = scan.has(FileScanner.PDF_JAVASCRIPT) || scan.has(FileScanner.PDF_JS)
            if (scan.has(FileScanner.PDF_LAUNCH)) findings += Finding(
                "PDF_LAUNCH", Severity.ALTO,
                "PDF tenta abrir outro programa",
                "O PDF contém o comando /Launch, que pede para executar um arquivo ou programa.",
            )
            if (hasJs) {
                val auto = scan.has(FileScanner.PDF_OPENACTION)
                findings += Finding(
                    "PDF_JAVASCRIPT", if (auto) Severity.ALTO else Severity.MEDIO,
                    if (auto) "PDF executa código ao ser aberto" else "PDF com JavaScript",
                    "Documentos comuns não precisam de JavaScript. Isso é usado para explorar falhas em leitores de PDF.",
                )
            }
            if (scan.has(FileScanner.PDF_EMBEDDED)) findings += Finding(
                "PDF_EMBEDDED", Severity.BAIXO,
                "PDF com outro arquivo dentro",
                "O PDF traz um anexo embutido. Não abra o anexo se não souber o que é.",
            )
        }

        // 7) Conteúdo de ZIP comum
        if (realType == RealType.ZIP) {
            val inner = scan.zipEntries.filter { e ->
                val x = FileTypeDetector.extensionOf(e.substringAfterLast('/'))
                FileTypeDetector.EXTENSION_CATEGORY[x] == FileCategory.EXECUTABLE && x !in setOf("bin", "so", "dll", "sh")
            }
            if (inner.isNotEmpty()) findings += Finding(
                "ZIP_HAS_EXECUTABLE", Severity.ALTO,
                "Arquivo compactado com programa dentro",
                "Contém: ${inner.take(3).joinToString(", ") { it.substringAfterLast('/') }}" +
                    (if (inner.size > 3) " e mais ${inner.size - 3}" else "") +
                    ". Vírus costumam chegar assim, dentro de um .zip.",
            )
            val innerDouble = scan.zipEntries.map { it.substringAfterLast('/') }.firstOrNull { doubleExtension(it) != null }
            if (innerDouble != null && inner.isEmpty()) findings += Finding(
                "ZIP_DOUBLE_EXTENSION", Severity.ALTO,
                "Arquivo interno com extensão dupla",
                "Dentro do ZIP há \"$innerDouble\", que finge ser outro tipo de arquivo.",
            )
            if (scan.zipEncrypted) findings += Finding(
                "ZIP_ENCRYPTED", Severity.MEDIO,
                "Compactado com senha",
                "Não é possível ver o que há dentro. Golpistas mandam .zip com senha justamente para escapar dos antivírus.",
            )
        }

        // 8) Páginas da web e SVG com código
        if (realType == RealType.HTML || realType == RealType.SVG) {
            val script = scan.has(FileScanner.HTML_SCRIPT)
            if (realType == RealType.SVG && script) findings += Finding(
                "SVG_SCRIPT", Severity.MEDIO,
                "Imagem SVG com código",
                "Esta imagem contém JavaScript. SVGs assim são usados para abrir páginas falsas.",
            ) else if (realType == RealType.HTML && !findings.any { it.code == "DISGUISED_HTML" }) findings += Finding(
                "HTML_FILE", Severity.BAIXO,
                "Página da web salva em arquivo",
                "Se recebeu como anexo, cuidado: é um jeito comum de mostrar uma tela de login falsa.",
            )
        }

        if (scan.size == 0L) findings += Finding("EMPTY", Severity.INFO, "Arquivo vazio", "O arquivo não tem conteúdo.")

        return FileAnalysis(
            fileName = fileName,
            size = scan.size,
            hashes = scan.hashes,
            realType = realType,
            extension = ext,
            findings = findings.sortedByDescending { it.severity },
            verdict = Verdict.from(findings),
            innerEntries = scan.zipEntries.size,
        )
    }

    private fun nameChecks(fileName: String, out: MutableList<Finding>) {
        if (fileName.contains('‮') || fileName.contains('‭') || fileName.contains('⁦') || fileName.contains('⁧')) {
            out += Finding(
                "RTLO_NAME", Severity.ALTO,
                "Nome com caractere invisível que inverte o texto",
                "O nome usa um caractere especial que faz \"fdp.exe\" aparecer como \"exe.pdf\". É truque de vírus.",
            )
        }
        doubleExtension(fileName)?.let { (fake, real) ->
            out += Finding(
                "DOUBLE_EXTENSION", Severity.ALTO,
                "Extensão dupla: parece .$fake, mas é .$real",
                "O nome \"${fileName.trim()}\" tenta parecer ${FileTypeDetector.EXTENSION_CATEGORY[fake]?.label ?: "outro tipo"}, " +
                    "mas o que vale é a última extensão (.$real). Ex.: boleto.pdf.apk é um aplicativo.",
            )
        }
    }

    companion object {
        /** Retorna (extensão falsa, extensão real) para nomes como "boleto.pdf.apk" ou "foto.jpg      .exe". */
        fun doubleExtension(name: String): Pair<String, String>? {
            val clean = name.trim().replace('‮', ' ').replace('‭', ' ')
            val parts = clean.split('.')
            if (parts.size < 3) return null
            val real = parts.last().trim().lowercase()
            val fake = parts[parts.size - 2].trim().lowercase()
            if (FileTypeDetector.EXTENSION_CATEGORY[real] != FileCategory.EXECUTABLE) return null
            val fakeCat = FileTypeDetector.EXTENSION_CATEGORY[fake] ?: return null
            if (fakeCat == FileCategory.EXECUTABLE) return null
            return fake to real
        }
    }
}
