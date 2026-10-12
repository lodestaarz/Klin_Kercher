package com.example.klin_kercher.core.url

/**
 * Funções sobre nomes de domínio: domínio registrável (a parte que alguém compra),
 * domínios-pai e reconhecimento de endereços IP, inclusive os disfarçados.
 *
 * Não usamos a Public Suffix List completa (≈ 250 KB) para manter o app leve.
 * A lista abaixo cobre os sufixos de dois níveis mais comuns no Brasil e no mundo,
 * além de plataformas onde cada subdomínio pertence a um dono diferente
 * (ex.: fulano.github.io não é do GitHub).
 */
object DomainUtils {

    /** Sufixos com mais de um nível. Os de um nível (com, br, xyz…) são tratados automaticamente. */
    private val MULTI_LEVEL_SUFFIXES: Set<String> = setOf(
        // Brasil (registro.br)
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br", "app.br", "dev.br",
        "eco.br", "emp.br", "eng.br", "esp.br", "etc.br", "far.br", "flog.br", "ind.br", "inf.br",
        "jus.br", "leg.br", "log.br", "mil.br", "mp.br", "nom.br", "ong.br", "psi.br", "rec.br",
        "srv.br", "tec.br", "tmp.br", "tur.br", "tv.br", "vlog.br", "wiki.br", "adm.br", "adv.br",
        "arq.br", "bio.br", "cnt.br", "ecn.br", "fot.br", "fst.br", "jor.br", "lel.br", "med.br",
        "not.br", "odo.br", "ppg.br", "pro.br", "qsl.br", "slg.br", "trd.br", "vet.br", "zlg.br",
        "sp.gov.br", "rj.gov.br", "mg.gov.br", "rs.gov.br", "pr.gov.br", "sc.gov.br", "ba.gov.br",
        "pe.gov.br", "ce.gov.br", "go.gov.br", "df.gov.br", "es.gov.br", "pa.gov.br", "am.gov.br",
        // Outros países
        "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.ar", "gob.ar", "com.mx", "gob.mx", "com.co", "com.pe", "com.uy", "com.py", "com.ve",
        "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
        "co.in", "net.in", "org.in", "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.sg",
        "com.my", "co.id", "co.th", "com.vn", "com.ph", "com.tr", "com.sa", "com.eg", "co.za",
        "co.il", "com.ua", "com.ru", "com.pt", "com.es", "co.ao", "co.mz",
        // Plataformas com subdomínios de terceiros (seção "private" da Public Suffix List)
        "github.io", "gitlab.io", "blogspot.com", "blogspot.com.br", "herokuapp.com", "firebaseapp.com",
        "web.app", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "appspot.com",
        "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com", "wixsite.com", "weebly.com",
        "glitch.me", "repl.co", "replit.app", "ngrok.io", "ngrok-free.app", "ngrok.app",
        "000webhostapp.com", "wordpress.com", "godaddysites.com", "square.site", "myshopify.com",
        "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "web.core.windows.net",
        "r2.dev", "onrender.com", "fly.dev", "surge.sh", "framer.app", "webflow.io", "carrd.co",
        "translate.goog", "ipfs.dweb.link", "trycloudflare.com",
    )

    private val PRIVATE_PLATFORM_SUFFIXES = setOf(
        "github.io", "gitlab.io", "blogspot.com", "blogspot.com.br", "herokuapp.com", "firebaseapp.com",
        "web.app", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "appspot.com",
        "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com", "wixsite.com", "weebly.com",
        "glitch.me", "repl.co", "replit.app", "ngrok.io", "ngrok-free.app", "ngrok.app",
        "000webhostapp.com", "wordpress.com", "godaddysites.com", "square.site", "myshopify.com",
        "duckdns.org", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "web.core.windows.net",
        "r2.dev", "onrender.com", "fly.dev", "surge.sh", "framer.app", "webflow.io", "carrd.co",
        "translate.goog", "ipfs.dweb.link", "trycloudflare.com",
    )

    /** Retorna o sufixo público do host (ex.: "com.br" para "www.nubank.com.br"). */
    fun publicSuffix(host: String): String {
        val labels = host.split('.')
        // procura o sufixo mais longo conhecido
        for (i in 0 until labels.size) {
            val candidate = labels.subList(i, labels.size).joinToString(".")
            if (candidate in MULTI_LEVEL_SUFFIXES && i > 0) return candidate
        }
        return labels.last()
    }

    /**
     * Domínio registrável: sufixo público + um rótulo.
     * "login.nubank.com.br" → "nubank.com.br"; "fulano.github.io" → "fulano.github.io".
     */
    fun registrableDomain(host: String): String {
        if (host.isEmpty() || isIpLiteral(host)) return host
        val suffix = publicSuffix(host)
        if (host == suffix) return host
        val withoutSuffix = host.removeSuffix(".$suffix")
        val label = withoutSuffix.substringAfterLast('.')
        return "$label.$suffix"
    }

    /** O rótulo principal do domínio registrável ("nubank" em "app.nubank.com.br"). */
    fun mainLabel(host: String): String {
        val reg = registrableDomain(host)
        if (isIpLiteral(reg)) return reg
        return reg.substringBefore('.')
    }

    /** Rótulos antes do domínio registrável ("login", "app" em "login.app.nubank.com.br"). */
    fun subdomainLabels(host: String): List<String> {
        val reg = registrableDomain(host)
        if (host == reg) return emptyList()
        return host.removeSuffix(".$reg").split('.').filter { it.isNotEmpty() }
    }

    /** Host e seus pais até o domínio registrável: a.b.site.com → [a.b.site.com, b.site.com, site.com]. */
    fun hostAndParents(host: String): List<String> {
        if (isIpLiteral(host)) return listOf(host)
        val reg = registrableDomain(host)
        val out = mutableListOf<String>()
        var current = host
        while (true) {
            out.add(current)
            if (current == reg || !current.contains('.')) break
            current = current.substringAfter('.')
        }
        return out
    }

    /** true se host for igual a [domain] ou subdomínio dele. */
    fun isSameOrSubdomain(host: String, domain: String): Boolean =
        host == domain || host.endsWith(".$domain")

    fun isPrivatePlatform(host: String): Boolean = PRIVATE_PLATFORM_SUFFIXES.any { isSameOrSubdomain(host, it) && host != it }

    fun isIpLiteral(host: String): Boolean =
        host.startsWith("[") || parseIpv4(host)?.let { it.canonical == host } == true

    /** Resultado da leitura de um host como IPv4, segundo as regras dos navegadores (WHATWG URL). */
    data class Ipv4(val canonical: String, val disguised: Boolean)

    /**
     * Navegadores aceitam IPv4 em formatos estranhos, muito usados para disfarçar:
     * "3232235777" (decimal único), "0xC0A80001" (hexadecimal), "0300.0250.0.1" (octal),
     * "192.168.1" (partes faltando). Retorna null se o host não for um IPv4.
     */
    fun parseIpv4(host: String): Ipv4? {
        if (host.isEmpty()) return null
        var parts = host.split('.')
        if (parts.last().isEmpty() && parts.size > 1) parts = parts.dropLast(1)
        if (parts.isEmpty() || parts.size > 4) return null
        // só é IPv4 se o último rótulo for numérico
        if (parseIpv4Number(parts.last()) == null) return null
        val numbers = parts.map { parseIpv4Number(it) ?: return null }
        var disguised = false
        for ((i, p) in parts.withIndex()) {
            val n = numbers[i]
            val isPlainDecimal = p.isNotEmpty() && p.all { it.isDigit() } && (p == "0" || !p.startsWith("0"))
            if (!isPlainDecimal) disguised = true
            if (i < numbers.size - 1 && n > 255) return null
        }
        if (parts.size != 4) disguised = true
        val last = numbers.last()
        val maxLast = 1L shl (8 * (5 - numbers.size))
        if (last >= maxLast) return null
        var value = last
        for (i in 0 until numbers.size - 1) value += numbers[i] shl (8 * (3 - i))
        val canonical = listOf(24, 16, 8, 0).joinToString(".") { ((value shr it) and 0xFF).toString() }
        return Ipv4(canonical, disguised)
    }

    private fun parseIpv4Number(part: String): Long? {
        if (part.isEmpty()) return null
        var s = part
        var radix = 10
        if (s.length >= 2 && (s.startsWith("0x") || s.startsWith("0X"))) {
            s = s.substring(2); radix = 16
            if (s.isEmpty()) return 0
        } else if (s.length >= 2 && s.startsWith("0")) {
            s = s.substring(1); radix = 8
        }
        if (s.length > 12) return null
        return s.toLongOrNull(radix)?.takeIf { it >= 0 }
    }
}
