package com.example.klin_kercher.core

import com.example.klin_kercher.core.file.FileAnalyzer
import com.example.klin_kercher.core.file.FileScanner
import com.example.klin_kercher.core.file.RealType
import com.example.klin_kercher.core.importer.ListImporter
import com.example.klin_kercher.core.url.UrlAnalyzer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class FileAndImporterTest {

    companion object {
        // Montado em partes para que o próprio código-fonte não seja acusado por antivírus.
        val EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}\$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*").toByteArray(Charsets.US_ASCII)
        const val EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        const val EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
        const val EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
    }

    private val lookup = InMemoryThreatLookup(hashes = mapOf(EICAR_SHA256 to "EICAR (arquivo de teste)"))
    private val analyzer = FileAnalyzer(lookup)

    private fun analyze(name: String, bytes: ByteArray) = analyzer.analyze(name, ByteArrayInputStream(bytes))
    private fun codes(name: String, bytes: ByteArray) = analyze(name, bytes).findings.map { it.code }.toSet()

    private fun zip(vararg entries: Pair<String, ByteArray>): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { z ->
            for ((name, data) in entries) {
                z.putNextEntry(ZipEntry(name)); z.write(data); z.closeEntry()
            }
        }
        return bos.toByteArray()
    }

    /** Entrega 1 byte por leitura, para testar padrões que caem na divisa entre leituras. */
    private class OneByteStream(input: InputStream) : FilterInputStream(input) {
        override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, minOf(1, len))
    }

    // ------------------------------------------------------------ hashes

    @Test fun hashesAreCorrectInOnePass() {
        val r = FileScanner().scan(ByteArrayInputStream(EICAR))
        assertEquals(EICAR_SHA256, r.hashes.sha256)
        assertEquals(EICAR_SHA1, r.hashes.sha1)
        assertEquals(EICAR_MD5, r.hashes.md5)
        assertEquals(68L, r.size)
    }

    @Test fun knownHashIsCritical() {
        val a = analyze("teste.txt", EICAR)
        assertEquals(Verdict.PERIGOSO, a.verdict)
        assertTrue(a.findings.any { it.code == "HASH_MATCH" && it.detail.contains("EICAR") })
        // sem a base, ainda é reconhecido pela assinatura de teste
        assertTrue("EICAR" in FileAnalyzer().analyze("x.com", ByteArrayInputStream(EICAR)).findings.map { it.code })
    }

    @Test fun markersAcrossReadBoundaries() {
        val pdf = "%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj 2 0 obj << /S /JavaScript /JS (app.alert(1)) >>".toByteArray()
        val r = FileScanner().scan(OneByteStream(ByteArrayInputStream(pdf)))
        assertTrue(r.has(FileScanner.PDF_JAVASCRIPT))
        assertTrue(r.has(FileScanner.PDF_JS))
        assertTrue(r.has(FileScanner.PDF_OPENACTION))
    }

    // ------------------------------------------------------------ tipos e disfarces

    @Test fun disguisedExecutable() {
        val exe = byteArrayOf(0x4D, 0x5A, 0x90.toByte(), 0) + ByteArray(200)
        val a = analyze("fatura.pdf", exe)
        assertEquals(RealType.PE_EXE, a.realType)
        assertEquals(Verdict.PERIGOSO, a.verdict)
        assertTrue("DISGUISED_EXECUTABLE" in a.findings.map { it.code })
    }

    @Test fun apkDetectedEvenWithWrongName() {
        val apk = zip("AndroidManifest.xml" to ByteArray(50), "classes.dex" to "dex\n035".toByteArray(), "res/x.png" to ByteArray(10))
        assertEquals(RealType.APK, analyze("app.apk", apk).realType)
        assertEquals(Verdict.SUSPEITO, analyze("app.apk", apk).verdict)
        val disguised = analyze("comprovante.jpg", apk)
        assertEquals(Verdict.PERIGOSO, disguised.verdict)
    }

    @Test fun doubleExtension() {
        assertTrue("DOUBLE_EXTENSION" in codes("boleto.pdf.apk", ByteArray(10)))
        assertTrue("DOUBLE_EXTENSION" in codes("foto.jpg        .exe", ByteArray(10)))
        assertFalse("DOUBLE_EXTENSION" in codes("relatorio.2024.pdf", "%PDF-1.4".toByteArray()))
        assertFalse("DOUBLE_EXTENSION" in codes("app-v1.2.apk", ByteArray(10)))
        assertTrue("RTLO_NAME" in codes("fatura‮fdp.exe", ByteArray(10)))
    }

    @Test fun officeMacros() {
        val docm = zip("[Content_Types].xml" to ByteArray(5), "word/document.xml" to ByteArray(5), "word/vbaProject.bin" to ByteArray(20))
        val a = analyze("contrato.docx", docm)
        assertEquals(RealType.OOXML, a.realType)
        val macro = a.findings.first { it.code == "OFFICE_MACRO" }
        assertEquals(Severity.ALTO, macro.severity) // .docx não deveria ter macro
        assertEquals(Severity.MEDIO, analyze("planilha.xlsm", docm).findings.first { it.code == "OFFICE_MACRO" }.severity)

        val clean = zip("[Content_Types].xml" to ByteArray(5), "word/document.xml" to ByteArray(5))
        assertEquals(Verdict.SEM_SINAIS, analyze("contrato.docx", clean).verdict)

        val ole = byteArrayOf(0xD0.toByte(), 0xCF.toByte(), 0x11, 0xE0.toByte(), 0xA1.toByte(), 0xB1.toByte(), 0x1A, 0xE1.toByte()) +
            ByteArray(500) + "_VBA_PROJECT".toByteArray(Charsets.UTF_16LE)
        assertTrue("OFFICE_MACRO" in codes("antigo.doc", ole))
    }

    @Test fun pdfJavascript() {
        val pdf = "%PDF-1.7\n<< /OpenAction << /S /JavaScript /JS (this.exportDataObject()) >> >>".toByteArray()
        val a = analyze("documento.pdf", pdf)
        assertEquals(Severity.ALTO, a.findings.first { it.code == "PDF_JAVASCRIPT" }.severity)
        val plain = "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj".toByteArray()
        assertEquals(Verdict.SEM_SINAIS, analyze("documento.pdf", plain).verdict)
    }

    @Test fun zipContents() {
        val z = zip("leia.txt" to ByteArray(5), "nota_fiscal.pdf.exe" to byteArrayOf(0x4D, 0x5A))
        val a = analyze("nota.zip", z)
        assertTrue("ZIP_HAS_EXECUTABLE" in a.findings.map { it.code })
        assertEquals(Verdict.PERIGOSO, a.verdict)

        // marca o primeiro item como protegido por senha (bit 0 das flags, posição 6 do cabeçalho)
        val enc = zip("documento.pdf" to ByteArray(30)).clone()
        enc[6] = (enc[6].toInt() or 1).toByte()
        assertTrue("ZIP_ENCRYPTED" in codes("documento.zip", enc))
    }

    @Test fun htmlPretendingToBePdf() {
        val html = "<!DOCTYPE html><html><body><form>Senha</form></body></html>".toByteArray()
        assertTrue("DISGUISED_HTML" in codes("boleto.pdf", html))
    }

    @Test fun ordinaryFilesHaveNoRisk() {
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) + ByteArray(100)
        assertEquals(Verdict.SEM_SINAIS, analyze("foto.png", png).verdict)
        assertEquals(Verdict.SEM_SINAIS, analyze("notas.txt", "Lista de compras\narroz\nfeijão".toByteArray()).verdict)
        assertEquals(RealType.TEXT, analyze("notas.txt", "abc".toByteArray()).realType)
    }

    // ------------------------------------------------------------ importação

    @Test fun importHashesInSeveralFormats() {
        val text = """
            # MalwareBazaar recent
            # "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash"
            "2026-10-01 10:00:00","${"a".repeat(64)}","${"b".repeat(32)}","${"c".repeat(40)}","x","f.exe","exe","app/x","AgentTesla","n/a","n/a","${"f".repeat(32)}"
            ${"D".repeat(64)}
            ${"e".repeat(32)}  ; comentário
            linha inválida
            ${"a".repeat(64)}
        """.trimIndent()
        val r = ListImporter.parseHashes(text.reader().buffered())
        assertEquals(5, r.hashes.size)
        assertEquals("AgentTesla", r.hashes.first().label)
        assertTrue(r.hashes.any { it.hash == "d".repeat(64) })
        assertFalse("imphash não é hash de arquivo", r.hashes.any { it.hash == "f".repeat(32) })
        assertEquals(1, r.skippedLines)
    }

    @Test fun importDomainsInSeveralFormats() {
        val text = """
            [Adblock Plus 2.0]
            ! comentário
            # comentário
            0.0.0.0 golpe-um.com
            127.0.0.1 localhost
            127.0.0.1	golpe-dois.net # tab
            ||golpe-tres.org^${'$'}third-party
            @@||exemplo-permitido.com^
            golpe-quatro.xyz
            *.golpe-cinco.top
            http://golpe-seis.shop/login/index.php
            https://drive.google.com/uc?id=abc123
            http://45.10.20.30:8080/bins/x86
            https://golpe-sete.com/
            texto qualquer
        """.trimIndent()
        val r = ListImporter.parseDomainsAndUrls(text.reader().buffered())
        val d = r.domains.map { it.domain }.toSet()
        assertEquals(
            setOf("golpe-um.com", "golpe-dois.net", "golpe-tres.org", "golpe-quatro.xyz", "golpe-cinco.top", "golpe-seis.shop",
                "45.10.20.30", "golpe-sete.com"),
            d,
        )
        val u = r.urls.map { it.key }.toSet()
        assertTrue("golpe-seis.shop/login/index.php" in u)
        assertTrue("drive.google.com/uc?id=abc123" in u) // só o endereço exato: Google Drive não é bloqueado
        assertFalse("drive.google.com" in d)
        assertEquals(2, r.skippedLines) // "localhost" e "texto qualquer"
    }

    @Test fun importUrlhausCsv() {
        val csv = """
            # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            "123","2026-10-01 10:00:00","http://golpe.example.net/a.apk","online","2026-10-01","malware_download","apk","https://urlhaus.abuse.ch/url/123/","x"
        """.trimIndent()
        val r = ListImporter.parseDomainsAndUrls(csv.reader().buffered())
        assertEquals("golpe.example.net/a.apk", r.urls.single().key)
        assertEquals("malware_download", r.urls.single().label)
    }

    @Test fun importedUrlsMatchAnalyzer() {
        val r = ListImporter.parseDomainsAndUrls("http://Site-Invadido.com.br/wp/boleto.php?id=1\n".reader().buffered())
        val lookup = InMemoryThreatLookup(urls = r.urls.associate { it.key to it.label }, domains = r.domains.associate { it.domain to it.label })
        val a = UrlAnalyzer(lookup).analyze("https://site-invadido.com.br/wp/boleto.php?id=1")
        assertTrue(a.findings.any { it.code == "BLOCKLIST" })
    }

    // ------------------------------------------------------------ base embutida

    /** Garante que os arquivos em assets/base (gerados por tools/atualizar_base.py) são lidos sem erro. */
    @Test fun bundledAssetsParse() {
        val dir = listOf("src/main/assets/base", "app/src/main/assets/base").map { java.io.File(it) }.firstOrNull { it.isDirectory }
            ?: return // executado fora do projeto
        val files = dir.listFiles().orEmpty().filter { it.name.endsWith(".txt") || it.name.endsWith(".csv") }
        assertTrue("nenhuma lista em ${dir.path}", files.isNotEmpty())
        var hashes = 0
        for (f in files) {
            val r = f.bufferedReader().use {
                if (f.name.startsWith("hashes_")) ListImporter.parseHashes(it) else ListImporter.parseDomainsAndUrls(it)
            }
            assertTrue("${f.name} está vazio", r.total > 0)
            hashes += r.hashes.size
            if (f.name == "hashes_padrao.txt") {
                assertTrue(r.hashes.any { it.hash == EICAR_SHA256 && it.label!!.startsWith("EICAR") })
            }
        }
        assertTrue(hashes >= 3)
    }
}
