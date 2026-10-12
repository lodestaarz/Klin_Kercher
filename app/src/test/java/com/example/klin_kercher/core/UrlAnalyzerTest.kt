package com.example.klin_kercher.core

import com.example.klin_kercher.core.url.DomainUtils
import com.example.klin_kercher.core.url.UrlAnalysis
import com.example.klin_kercher.core.url.UrlAnalyzer
import com.example.klin_kercher.core.url.UrlExtractor
import com.example.klin_kercher.core.url.UrlParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlAnalyzerTest {

    private val lookup = InMemoryThreatLookup(
        domains = mapOf("golpe-exemplo.test" to "phishing", "1.2.3.4" to null),
        urls = mapOf("site-legitimo.com.br/pagina-invadida/boleto.php" to "malware_download"),
    )
    private val analyzer = UrlAnalyzer(lookup)

    private fun analyze(s: String) = analyzer.analyze(s)
    private fun UrlAnalysis.codes() = findings.map { it.code }.toSet()
    private fun UrlAnalysis.allCodes(): Set<String> = codes() + (redirect?.allCodes() ?: emptySet())

    // ------------------------------------------------------------ sites legítimos

    @Test fun officialSitesHaveNoRisk() {
        for (u in listOf(
            "https://www.nubank.com.br", "nubank.com.br/cartao", "https://www.itau.com.br/conta",
            "https://www.gov.br/receitafederal/pt-br", "https://meu.inss.gov.br", "https://www.google.com.br/search?q=nubank",
            "https://www.mercadolivre.com.br/ofertas", "https://www.bb.com.br", "https://www.caixa.gov.br",
            "https://www.amazon.de", "https://accounts.google.com/signin", "https://www.correios.com.br/rastreamento",
        )) {
            val r = analyze(u)
            assertEquals("$u → ${r.findings}", Verdict.SEM_SINAIS, r.verdict)
        }
    }

    @Test fun ordinarySitesHaveNoRisk() {
        for (u in listOf(
            "https://pt.wikipedia.org/wiki/Brasil", "https://g1.globo.com", "https://www.uol.com.br",
            "https://github.com/user/repo", "https://www.estadao.com.br/economia/nubank-lucro-trimestre",
            "https://pão.com.br", "https://cloud.com", "https://twister.com.br", "https://finance.yahoo.com",
            "https://americana-imoveis.com.br", "https://www.amazonas.am.gov.br",
        )) {
            val r = analyze(u)
            assertEquals("$u → ${r.findings}", Verdict.SEM_SINAIS, r.verdict)
        }
    }

    @Test fun officialDomainIsRecognized() {
        val r = analyze("https://app.nubank.com.br/login")
        assertEquals("Nubank", r.officialBrand)
        assertTrue("OFFICIAL_DOMAIN" in r.codes())
    }

    // ------------------------------------------------------------ lista local

    @Test fun blocklistMatchesDomainAndSubdomain() {
        assertEquals(Verdict.PERIGOSO, analyze("http://golpe-exemplo.test").verdict)
        val sub = analyze("https://login.seguro.golpe-exemplo.test/entrar")
        assertEquals(Verdict.PERIGOSO, sub.verdict)
        assertTrue("BLOCKLIST" in sub.codes())
    }

    @Test fun blocklistMatchesExactUrlIgnoringScheme() {
        val r = analyze("https://site-legitimo.com.br/pagina-invadida/boleto.php")
        assertTrue("BLOCKLIST" in r.codes())
        assertFalse("BLOCKLIST" in analyze("https://site-legitimo.com.br/").codes())
    }

    @Test fun blocklistMatchesDisguisedIp() {
        // 16909060 = 1.2.3.4
        val r = analyze("http://16909060/painel")
        assertTrue(r.codes().containsAll(listOf("BLOCKLIST", "IP_DISGUISED")))
    }

    // ------------------------------------------------------------ marcas

    @Test fun typoOfBrandIsDangerous() {
        val r = analyze("https://nubnak.com.br")
        assertEquals(Verdict.PERIGOSO, r.verdict)
        assertTrue("BRAND_TYPO" in r.codes())
    }

    @Test fun leetSpeakIsDetected() {
        for (u in listOf("http://g00gle.com", "https://paypa1.com/login", "1tau-cartao.com")) {
            val r = analyze(u)
            assertEquals(u, Verdict.PERIGOSO, r.verdict)
            assertTrue("$u ${r.codes()}", "BRAND_LEET" in r.codes())
        }
    }

    @Test fun brandInsideOtherDomain() {
        val r = analyze("https://nubank-seguranca.xyz/atualizar")
        assertEquals(Verdict.PERIGOSO, r.verdict)
        assertTrue("BRAND_IN_HOST" in r.codes())
        assertTrue(r.findings.first { it.code == "BRAND_IN_HOST" }.detail.contains("seguranca"))
    }

    @Test fun officialDomainUsedAsSubdomain() {
        val r = analyze("https://mercadolivre.com.br.ofertas.shop/produto")
        assertEquals(Verdict.PERIGOSO, r.verdict)
        assertTrue("BRAND_OFFICIAL_AS_SUBDOMAIN" in r.codes())
    }

    @Test fun brandOnFreeHostingPlatform() {
        val r = analyze("https://nubank-app.github.io/")
        assertEquals(Verdict.PERIGOSO, r.verdict)
    }

    @Test fun cyrillicHomograph() {
        // "nubаnk" com "а" cirílico (U+0430)
        val r = analyze("https://nubаnk.com.br")
        assertEquals(Verdict.PERIGOSO, r.verdict)
        assertTrue("HOMOGRAPH" in r.codes())
        // mesmo vindo em punycode
        val p = UrlParser.parse("https://nubаnk.com.br")!!
        assertTrue(p.host.startsWith("xn--"))
        assertTrue("HOMOGRAPH" in analyze("https://${p.host}").codes())
    }

    @Test fun allCyrillicLookalike() {
        // "аррӏе.com" totalmente em cirílico imita apple.com
        val r = analyze("https://аррӏе.com")
        assertEquals(Verdict.PERIGOSO, r.verdict)
    }

    @Test fun mixedScripts() {
        val r = analyze("https://lojα-ofertas.com") // α grego no meio de latinas
        assertTrue(r.codes().toString(), "MIXED_SCRIPTS" in r.codes())
    }

    @Test fun weakBrandAloneIsOnlySuspicious() {
        val r = analyze("https://caixa-ofertas-loja.com.br")
        assertTrue("BRAND_IN_HOST" in r.codes())
        val alert = analyze("https://caixa-desbloqueio.com")
        assertEquals(Verdict.PERIGOSO, alert.verdict)
    }

    // ------------------------------------------------------------ truques

    @Test fun atSignTrick() {
        val r = analyze("https://www.bb.com.br@golpe.example.com/login")
        assertEquals(Verdict.PERIGOSO, r.verdict)
        assertTrue("AT_TRICK" in r.codes())
        assertEquals("golpe.example.com", r.parsed!!.host)
    }

    @Test fun disguisedIpFormats() {
        for (h in listOf("3232235777", "0xC0A80101", "0300.0250.1.1", "192.168.257")) {
            val ip = DomainUtils.parseIpv4(h.lowercase())
            assertNotNull(h, ip)
            assertTrue(h, ip!!.disguised)
            assertEquals(h, "192.168.1.1", ip.canonical)
        }
        assertFalse(DomainUtils.parseIpv4("192.168.1.1")!!.disguised)
        assertNull(DomainUtils.parseIpv4("example.com"))
        assertEquals(Verdict.PERIGOSO, analyze("http://0xC0A80101/").verdict)
    }

    @Test fun plainIpIsSuspicious() {
        val r = analyze("http://45.67.89.10/fatura")
        assertTrue("IP_HOST" in r.codes())
        assertTrue(r.verdict != Verdict.SEM_SINAIS)
    }

    @Test fun shortenerIsSuspicious() {
        val r = analyze("https://bit.ly/3xYzAbc")
        assertEquals(Verdict.SUSPEITO, r.verdict)
        assertTrue("SHORTENER" in r.codes())
    }

    @Test fun apkDownloadIsDangerous() {
        assertTrue("EXECUTABLE_DOWNLOAD" in analyze("https://atualizacao-app.com/Banco.apk").codes())
        assertTrue("EXECUTABLE_DOWNLOAD" in analyze("https://site.com/download.php?arquivo=app.apk").codes())
        assertEquals(Verdict.PERIGOSO, analyze("http://45.67.89.10/app.apk").verdict)
    }

    @Test fun nonWebSchemes() {
        assertEquals(Verdict.PERIGOSO, analyze("javascript:alert(document.cookie)").verdict)
        assertEquals(Verdict.PERIGOSO, analyze("data:text/html;base64,PHNjcmlwdD4=").verdict)
    }

    @Test fun freeTld() {
        assertTrue("FREE_TLD" in analyze("http://premio-pix.tk").codes())
    }

    // ------------------------------------------------------------ redirecionamentos

    @Test fun googleRedirectAnalyzesDestination() {
        val r = analyze("https://www.google.com/url?q=https://nubank-seguranca.xyz/login&sa=D")
        assertNotNull(r.redirect)
        assertEquals("nubank-seguranca.xyz", r.redirect!!.parsed!!.host)
        assertEquals(Verdict.PERIGOSO, r.verdict)
        assertTrue("REDIRECT_VIA_TRUSTED" in r.codes())
    }

    @Test fun encodedAndNestedRedirect() {
        val inner = "https%3A%2F%2Fl.facebook.com%2Fl.php%3Fu%3Dhttps%253A%252F%252Fg00gle.com%252F"
        val r = analyze("https://www.google.com/url?q=$inner")
        assertEquals(Verdict.PERIGOSO, r.verdict)
        assertTrue(r.allCodes().contains("BRAND_LEET"))
    }

    @Test fun redirectToOfficialSiteIsFine() {
        val r = analyze("https://www.google.com/url?q=https://www.nubank.com.br/")
        assertEquals(Verdict.SEM_SINAIS, r.verdict)
    }

    // ------------------------------------------------------------ leitura e extração

    @Test fun parserHandlesOddInput() {
        val p = UrlParser.parse("  HTTPS://WWW.Nubank.com.br.:443/a?b=1#c ")!!
        assertEquals("www.nubank.com.br", p.host)
        assertEquals(443, p.port)
        assertEquals("/a", p.path)
        assertEquals("b=1", p.query)
        assertNull(UrlParser.parse("isto não é um link"))
        assertNull(UrlParser.parse("mailto:alguem@exemplo.com"))
        assertEquals("exemplo.com", UrlParser.parse("https:\\\\exemplo.com\\x")!!.host)
    }

    @Test fun registrableDomain() {
        assertEquals("nubank.com.br", DomainUtils.registrableDomain("a.b.nubank.com.br"))
        assertEquals("fulano.github.io", DomainUtils.registrableDomain("www.fulano.github.io"))
        assertEquals("exemplo.co.uk", DomainUtils.registrableDomain("loja.exemplo.co.uk"))
        assertEquals(listOf("a.b.site.com", "b.site.com", "site.com"), DomainUtils.hostAndParents("a.b.site.com"))
    }

    @Test fun extractsLinksFromMessage() {
        val msg = "Seu pacote foi TAXADO! Pague em https://correios-taxa.com/pagar?id=9 (prazo hoje). " +
            "Dúvidas: www.exemplo.com.br ou fale com suporte@empresa.com. Veja também nubank-seguranca.xyz."
        val links = UrlExtractor.extract(msg)
        assertEquals(listOf("https://correios-taxa.com/pagar?id=9", "www.exemplo.com.br", "nubank-seguranca.xyz"), links)
    }

    @Test fun osaDistance() {
        assertEquals(1, UrlAnalyzer.osaDistance("nubnak", "nubank"))
        assertEquals(1, UrlAnalyzer.osaDistance("gogle", "google"))
        assertEquals(0, UrlAnalyzer.osaDistance("abc", "abc"))
        assertEquals(3, UrlAnalyzer.osaDistance("abc", "xyz"))
    }
}
