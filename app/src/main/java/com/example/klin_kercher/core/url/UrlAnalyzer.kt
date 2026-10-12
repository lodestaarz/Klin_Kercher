package com.example.klin_kercher.core.url

import com.example.klin_kercher.core.Finding
import com.example.klin_kercher.core.InMemoryThreatLookup
import com.example.klin_kercher.core.Severity
import com.example.klin_kercher.core.ThreatLookup
import com.example.klin_kercher.core.ThreatMatch
import com.example.klin_kercher.core.Verdict

/** Resultado da análise de um link. */
data class UrlAnalysis(
    val input: String,
    val parsed: ParsedUrl?,
    val findings: List<Finding>,
    /** Veredito final, já considerando o destino de um redirecionamento. */
    val verdict: Verdict,
    /** Nome da marca, quando o endereço é oficial dela. */
    val officialBrand: String?,
    /** Análise do site de destino, quando o link redireciona (google.com/url?q=…). */
    val redirect: UrlAnalysis?,
) {
    /** false quando o texto não pôde ser lido como endereço. */
    val isRecognized: Boolean get() = parsed != null || findings.isNotEmpty()
}

/**
 * Analisa links totalmente no aparelho, sem acessar a internet.
 *
 * Verifica: lista local de bloqueio (com subdomínios), imitação de marcas (nome dentro do endereço,
 * erros de digitação, números no lugar de letras, letras de outros alfabetos), truques de endereço
 * (@, IP disfarçado, encurtadores, download de .apk etc.) e redirecionamentos.
 */
class UrlAnalyzer(
    private val lookup: ThreatLookup = InMemoryThreatLookup.EMPTY,
    private val brands: List<Brand> = BrandCatalog.brands,
) {

    fun analyze(input: String): UrlAnalysis = analyze(input, depth = 0)

    private fun analyze(input: String, depth: Int): UrlAnalysis {
        val findings = mutableListOf<Finding>()

        UrlParser.nonWebScheme(input)?.let { scheme ->
            findings += nonWebSchemeFinding(scheme)
            return UrlAnalysis(input, null, findings, Verdict.from(findings), null, null)
        }

        val p = UrlParser.parse(input)
            ?: return UrlAnalysis(input, null, emptyList(), Verdict.SEM_SINAIS, null, null)

        val host = p.canonicalHost
        val isIp = p.ipv4 != null || p.isIpv6

        // 1) Lista local de ameaças
        val match = lookup.matchUrl(p.lookupKeys()) ?: lookup.matchDomain(DomainUtils.hostAndParents(host))
        if (match != null) findings += blocklistFinding(match)

        // 2) Domínio oficial?
        val official = if (isIp) null else brands.firstOrNull { it.isOfficialHost(p.host) }
        if (official != null) {
            findings += Finding(
                "OFFICIAL_DOMAIN", Severity.INFO,
                "Endereço oficial de ${official.name}",
                "O domínio ${p.registrableDomain} pertence a ${official.name}.",
            )
        }

        // 3) Imitação de marca e alfabetos
        if (!isIp && official == null) {
            brandChecks(p, findings)
        }
        if (!isIp) unicodeChecks(p, findings)

        // 4) Truques no endereço
        trickChecks(p, official, findings)

        // 5) Redirecionamento
        var redirect: UrlAnalysis? = null
        if (depth < MAX_REDIRECT_DEPTH) {
            val target = findRedirectTarget(p)
            if (target != null) {
                val nested = analyze(target, depth + 1)
                if (nested.parsed != null && nested.parsed.canonicalHost != host) {
                    redirect = nested
                    findings += Finding(
                        "REDIRECT", Severity.INFO,
                        "Leva para outro site",
                        "Este link redireciona para ${nested.parsed.unicodeHost}. Analisamos o destino também.",
                    )
                    if (official != null && nested.parsed.registrableDomain != p.registrableDomain && nested.officialBrand == null) {
                        findings += Finding(
                            "REDIRECT_VIA_TRUSTED", Severity.BAIXO,
                            "Usa um site conhecido para esconder o destino",
                            "O link começa em ${official.name}, mas quem abre a página é ${nested.parsed.registrableDomain}.",
                        )
                    }
                }
            }
        }

        val own = Verdict.from(findings)
        val verdict = if (redirect != null) Verdict.worst(own, redirect.verdict) else own
        return UrlAnalysis(input, p, findings.sortedByDescending { it.severity }, verdict, official?.name, redirect)
    }

    // ------------------------------------------------------------------ marcas

    private fun brandChecks(p: ParsedUrl, out: MutableList<Finding>) {
        val skHost = Confusables.latinSkeleton(p.unicodeHost)
        val usedOtherAlphabet = skHost != p.unicodeHost && Confusables.scripts(p.unicodeHost).any { it != Character.UnicodeScript.LATIN }

        // Letras de outro alfabeto formando exatamente um endereço oficial: nubаnk.com.br (com "а" cirílico)
        if (skHost != p.host) {
            val imitated = brands.firstOrNull { it.isOfficialHost(skHost) }
            if (imitated != null) {
                out += Finding(
                    "HOMOGRAPH", Severity.ALTO,
                    "Imita o endereço de ${imitated.name} com letras falsas",
                    "Na tela parece \"$skHost\", mas o endereço usa letras de outro alfabeto ou com acento. " +
                        "O endereço real é ${p.host}.",
                )
                return
            }
        }

        val suffix = DomainUtils.publicSuffix(skHost)
        val reg = DomainUtils.registrableDomain(skHost)
        val mainLabel = reg.removeSuffix(".$suffix")
        val subLabels = DomainUtils.subdomainLabels(skHost)
        val subPart = subLabels.joinToString(".")
        val words = suspiciousWords(skHost)

        val mainJoined = mainLabel.replace("-", "")
        val mainTokens = mainLabel.split('-').filter { it.isNotEmpty() }
        val subJoined = subLabels.joinToString("").replace("-", "")
        val subTokens = subLabels.flatMap { it.split('-') }.filter { it.isNotEmpty() }

        var brandFindings = 0
        for (brand in brands) {
            if (brandFindings >= 2) break
            if (brand.isOfficialHost(skHost)) continue

            // Endereço oficial inteiro usado como subdomínio: mercadolivre.com.br.ofertas.shop
            val disguisedOfficial = brand.officialDomains.firstOrNull {
                it.contains('.') && ".$subPart.".contains(".$it.")
            }
            if (disguisedOfficial != null) {
                out += Finding(
                    "BRAND_OFFICIAL_AS_SUBDOMAIN", Severity.ALTO,
                    "Disfarça o endereço de ${brand.name}",
                    "O link começa com \"$disguisedOfficial\", mas o site que abre é $reg. " +
                        "O que vale é o final do endereço, não o começo.",
                )
                brandFindings++
                continue
            }

            val inMain = keywordHit(brand, mainJoined, mainTokens)
            val inSub = if (inMain == null) keywordHit(brand, subJoined, subTokens) else null
            val hit = inMain ?: inSub ?: continue

            val where = if (inMain != null) "no nome do site ($reg)" else "no começo do endereço, mas o site é $reg"
            val leetNote = if (hit.viaLeet) " Ele troca letras por números ou símbolos para enganar." else ""
            val alphaNote = if (usedOtherAlphabet) " Usa letras de outro alfabeto que imitam as nossas." else ""
            val wordsNote = if (words.isNotEmpty()) " Também usa palavras comuns em golpes: ${words.joinToString(", ")}." else ""
            val severity = if (brand.weak && words.isEmpty() && !hit.viaLeet) Severity.MEDIO else Severity.ALTO
            out += Finding(
                if (hit.viaLeet) "BRAND_LEET" else "BRAND_IN_HOST", severity,
                "Usa o nome de ${brand.name}, mas não é um site oficial",
                "Aparece \"${hit.term}\" $where, que não está entre os endereços oficiais conhecidos (${brand.officialDomains.filter { it.contains('.') }.take(2).joinToString(", ")}…)." +
                    leetNote + alphaNote + wordsNote,
            )
            brandFindings++
        }

        if (brandFindings == 0) {
            typoCheck(mainJoined, mainTokens, reg)?.let {
                out += it
                brandFindings++
            }
        }

        if (brandFindings == 0 && words.isNotEmpty()) {
            out += Finding(
                "SUSPICIOUS_WORDS", if (words.size >= 2) Severity.MEDIO else Severity.BAIXO,
                "Palavras comuns em golpes no endereço",
                "O endereço contém: ${words.joinToString(", ")}. Sites oficiais raramente usam isso no nome.",
            )
        }

        // marca citada no caminho junto com palavra de golpe: site-qualquer.com/nubank/login
        if (brandFindings == 0) {
            val path = Confusables.latinSkeleton(UrlParser.percentDecode(p.path)).replace("-", "").replace("_", "")
            val brandInPath = brands.firstOrNull { b ->
                b.keywords.any { k -> k.length >= 5 && !b.weak && path.contains(k) }
            }
            if (brandInPath != null && SUSPICIOUS_WORDS.any { path.contains(it) }) {
                out += Finding(
                    "BRAND_IN_PATH", Severity.MEDIO,
                    "Cita ${brandInPath.name}, mas o site é outro",
                    "O nome da marca aparece no caminho do link junto com termos de login ou pagamento, porém a página é de $reg, não de ${brandInPath.name}.",
                )
            }
        }
    }

    private data class Hit(val term: String, val viaLeet: Boolean)

    private fun keywordHit(brand: Brand, joined: String, tokens: List<String>): Hit? {
        if (joined.isEmpty()) return null
        val variants = listOf(joined to false) + Confusables.leetVariants(joined).map { it to true }
        for ((text, leet) in variants) {
            var cleaned = text
            for (ex in brand.excludes) cleaned = cleaned.replace(ex, "#")
            for (k in brand.keywords) if (cleaned.contains(k)) return Hit(k, leet)
        }
        for (t in tokens) {
            val tokenVariants = listOf(t to false) + Confusables.leetVariants(t).map { it to true }
            for ((tv, leet) in tokenVariants) if (tv in brand.tokens) return Hit(tv, leet)
        }
        return null
    }

    private fun typoCheck(mainJoined: String, mainTokens: List<String>, reg: String): Finding? {
        val candidates = (listOf(mainJoined) + mainTokens).filter { it.length >= 6 }.distinct()
        for (c in candidates) {
            if (c in BrandCatalog.allOfficialLabels || c in TYPO_SKIP) continue
            for (brand in brands) {
                for (target in brand.typoTargets) {
                    if (c == target) continue
                    val maxDist = when {
                        target.length >= 9 -> 2
                        target.length >= 6 -> 1
                        else -> 0
                    }
                    if (maxDist == 0 || kotlin.math.abs(c.length - target.length) > maxDist) continue
                    val d = osaDistance(c, target)
                    if (d in 1..maxDist) {
                        return Finding(
                            "BRAND_TYPO", Severity.ALTO,
                            "Nome parecido com ${brand.name}",
                            "\"$c\" lembra \"$target\", mas o site é $reg, que não é de ${brand.name}. " +
                                "Endereço oficial: ${brand.officialDomains.first { it.contains('.') }}.",
                        )
                    }
                }
            }
        }
        return null
    }

    private fun suspiciousWords(skHost: String): List<String> {
        val reg = DomainUtils.registrableDomain(skHost)
        val suffix = DomainUtils.publicSuffix(skHost)
        val text = skHost.removeSuffix(".$suffix").replace("-", "").replace(".", " ")
        if (reg == skHost && text.length < 4) return emptyList()
        return SUSPICIOUS_WORDS.filter { text.contains(it) }.take(4)
    }

    // ---------------------------------------------------------------- alfabetos

    private fun unicodeChecks(p: ParsedUrl, out: MutableList<Finding>) {
        if (!Confusables.hasNonAscii(p.unicodeHost)) return
        if (out.any { it.code == "HOMOGRAPH" }) return
        val labels = p.unicodeHost.split('.')
        val mixed = labels.any { Confusables.scripts(it).size > 1 }
        val nonLatin = Confusables.scripts(p.unicodeHost).filter { it != Character.UnicodeScript.LATIN }
        when {
            mixed -> out += Finding(
                "MIXED_SCRIPTS", Severity.ALTO,
                "Mistura letras de alfabetos diferentes",
                "O endereço \"${p.unicodeHost}\" mistura letras latinas com letras de outro alfabeto (${nonLatin.joinToString { scriptName(it) }}). " +
                    "Isso é usado para imitar sites conhecidos. Endereço real: ${p.host}.",
            )
            nonLatin.isNotEmpty() && labels.any { l ->
                val sk = Confusables.latinSkeleton(l)
                sk != l && sk.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
            } -> out += Finding(
                "LOOKALIKE_SCRIPT", Severity.MEDIO,
                "Letras de outro alfabeto que parecem latinas",
                "\"${p.unicodeHost}\" é escrito em ${nonLatin.joinToString { scriptName(it) }}, mas parece \"${Confusables.latinSkeleton(p.unicodeHost)}\". Endereço real: ${p.host}.",
            )
            else -> out += Finding(
                "IDN", Severity.INFO,
                "Endereço com acentos ou caracteres especiais",
                "Confira o endereço com atenção: ${p.unicodeHost} (registrado como ${p.host}).",
            )
        }
    }

    private fun scriptName(s: Character.UnicodeScript): String = when (s) {
        Character.UnicodeScript.CYRILLIC -> "cirílico"
        Character.UnicodeScript.GREEK -> "grego"
        Character.UnicodeScript.ARMENIAN -> "armênio"
        Character.UnicodeScript.LATIN -> "latino"
        Character.UnicodeScript.HAN -> "chinês"
        Character.UnicodeScript.ARABIC -> "árabe"
        Character.UnicodeScript.HEBREW -> "hebraico"
        else -> s.name.lowercase()
    }

    // ------------------------------------------------------------------- truques

    private fun trickChecks(p: ParsedUrl, official: Brand?, out: MutableList<Finding>) {
        val host = p.canonicalHost
        val reg = p.registrableDomain

        if (!p.userInfo.isNullOrEmpty()) {
            val fake = p.userInfo.substringBefore(':')
            out += if (fake.contains('.')) Finding(
                "AT_TRICK", Severity.ALTO,
                "Truque do @ no endereço",
                "O link parece ser de \"$fake\", mas tudo antes do @ é ignorado. O site que abre é ${p.unicodeHost}.",
            ) else Finding(
                "USERINFO", Severity.MEDIO,
                "Endereço com usuário embutido",
                "O link tem \"${p.userInfo}@\" antes do site. Isso é incomum e pode esconder o destino real.",
            )
        }

        p.ipv4?.let { ip ->
            out += if (ip.disguised) Finding(
                "IP_DISGUISED", Severity.ALTO,
                "Endereço IP disfarçado",
                "\"${p.host}\" é, na verdade, o IP ${ip.canonical} escrito de forma estranha para não ser reconhecido.",
            ) else Finding(
                "IP_HOST", Severity.MEDIO,
                "Usa um número de IP em vez de nome",
                "Sites legítimos quase nunca enviam links como ${ip.canonical}. É comum em golpes e downloads de vírus.",
            )
        }
        if (p.isIpv6) out += Finding(
            "IPV6_HOST", Severity.MEDIO,
            "Usa um endereço IPv6 em vez de nome",
            "Links para endereços numéricos (${p.host}) são incomuns e escondem quem é o dono do site.",
        )

        if (p.hostWasPercentEncoded) out += Finding(
            "HOST_ENCODED", Severity.MEDIO,
            "Nome do site codificado",
            "O nome do site foi escrito com códigos (%xx) para ficar ilegível. O site real é ${p.unicodeHost}.",
        )

        if (p.port != null && p.port != 80 && p.port != 443) out += Finding(
            "ODD_PORT", Severity.BAIXO,
            "Porta incomum (${p.port})",
            "Sites comuns não usam \":${p.port}\" no endereço.",
        )

        if (p.scheme == "http" && !p.schemeAssumed) out += Finding(
            "NO_HTTPS", Severity.BAIXO,
            "Sem conexão segura (http)",
            "Os dados enviados para este endereço não são protegidos. Nunca digite senhas em sites http.",
        )

        if (reg in SHORTENERS || host in SHORTENERS) out += Finding(
            "SHORTENER", Severity.MEDIO,
            "Link encurtado esconde o destino",
            "$reg é um encurtador: não dá para saber, sem abrir, para onde ele leva. " +
                "Desconfie se recebeu por mensagem ou e-mail.",
        )

        val lastSegment = UrlParser.percentDecode(p.path.substringAfterLast('/')).lowercase()
        val paramFiles = UrlParser.queryParams(p.query).map { it.second.lowercase().substringAfterLast('/') }
        val fileNames = listOf(lastSegment) + paramFiles
        val exe = fileNames.firstNotNullOfOrNull { n -> EXECUTABLE_EXTENSIONS.firstOrNull { n.endsWith(".$it") } }
        if (exe != null) {
            out += Finding(
                "EXECUTABLE_DOWNLOAD", Severity.ALTO,
                if (exe == "apk" || exe == "xapk" || exe == "apks") "Baixa um aplicativo (.apk)" else "Baixa um programa (.$exe)",
                if (exe.startsWith("apk") || exe == "xapk") "Instalar aplicativos fora da Play Store é a forma mais comum de golpe com vírus bancário. " +
                    "Bancos e lojas nunca pedem isso por mensagem."
                else "O link baixa um arquivo executável, que pode instalar vírus.",
            )
        } else {
            val arc = fileNames.firstNotNullOfOrNull { n -> ARCHIVE_EXTENSIONS.firstOrNull { n.endsWith(".$it") } }
            if (arc != null) out += Finding(
                "ARCHIVE_DOWNLOAD", Severity.BAIXO,
                "Baixa um arquivo compactado (.$arc)",
                "Arquivos compactados podem esconder programas. Verifique o arquivo no Klin Kercher antes de abrir.",
            )
        }

        if (official == null && p.ipv4 == null && !p.isIpv6) {
            val tld = host.substringAfterLast('.')
            when (tld) {
                in FREE_TLDS -> out += Finding(
                    "FREE_TLD", Severity.MEDIO,
                    "Terminação gratuita (.$tld)",
                    "Domínios .$tld são gratuitos e muito usados em golpes.",
                )
                in RISKY_TLDS -> out += Finding(
                    "RISKY_TLD", Severity.BAIXO,
                    "Terminação muito usada em golpes (.$tld)",
                    "Domínios .$tld são baratos e aparecem com frequência em links falsos.",
                )
            }
            val subs = DomainUtils.subdomainLabels(host)
            if (subs.size >= 4) out += Finding(
                "MANY_SUBDOMAINS", Severity.BAIXO,
                "Endereço com muitas partes",
                "O endereço tem ${subs.size} partes antes do site real ($reg), um jeito de esconder o nome verdadeiro.",
            )
            if (host.length > 60) out += Finding(
                "LONG_HOST", Severity.BAIXO,
                "Nome de site muito longo",
                "Nomes longos demais costumam ser usados para que você não veja o final do endereço.",
            )
            if (DomainUtils.mainLabel(host).count { it == '-' } >= 3) out += Finding(
                "MANY_HYPHENS", Severity.BAIXO,
                "Muitos hífens no nome",
                "Nomes como \"a-b-c-d.com\" são típicos de sites falsos criados às pressas.",
            )
        }
    }

    // --------------------------------------------------------------- redirecionamento

    private fun findRedirectTarget(p: ParsedUrl): String? {
        val params = UrlParser.queryParams(p.query)
        val ordered = params.sortedBy { if (it.first.lowercase() in REDIRECT_PARAMS) 0 else 1 }
        for ((_, value) in ordered) {
            var v = value.trim()
            repeat(2) { if (v.contains('%')) v = UrlParser.percentDecode(v) }
            val lower = v.lowercase()
            if (lower.startsWith("http://") || lower.startsWith("https://")) return v
            if (lower.startsWith("//") && v.length > 3) return "https:$v"
            if (lower.startsWith("www.") && v.contains('.')) return v
        }
        // fragmento com endereço completo (ex.: site.com/#https://outro.com)
        p.fragment?.let { f ->
            val d = UrlParser.percentDecode(f)
            if (d.startsWith("http://") || d.startsWith("https://")) return d
        }
        return null
    }

    // ------------------------------------------------------------------- outros

    private fun nonWebSchemeFinding(scheme: String): Finding = when (scheme) {
        "javascript", "vbscript" -> Finding(
            "SCRIPT_SCHEME", Severity.ALTO,
            "Não é um site: é um código ($scheme:)",
            "Ao tocar, este \"link\" executa um código no navegador. Não abra.",
        )
        "data" -> Finding(
            "DATA_SCHEME", Severity.ALTO,
            "Página escondida dentro do link (data:)",
            "O conteúdo vem embutido no próprio link, técnica usada para criar páginas falsas sem site.",
        )
        else -> Finding(
            "OTHER_SCHEME", Severity.MEDIO,
            "Link incomum ($scheme:)",
            "Este link não abre um site normal e pode acionar recursos do aparelho.",
        )
    }

    private fun blocklistFinding(m: ThreatMatch): Finding {
        val what = when (m.kind) {
            ThreatMatch.Kind.URL -> "Este endereço"
            else -> "O site ${m.value}"
        }
        val label = m.label?.takeIf { it.isNotBlank() }?.let { " Tipo: $it." } ?: ""
        val src = m.source?.let { " Fonte: $it." } ?: ""
        return Finding(
            "BLOCKLIST", Severity.CRITICO,
            "Está na lista de ameaças conhecidas",
            "$what consta na base local de links maliciosos.$label$src",
        )
    }

    companion object {
        const val MAX_REDIRECT_DEPTH = 3

        val SHORTENERS = setOf(
            "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "ow.ly", "buff.ly",
            "cutt.ly", "rebrand.ly", "shorturl.at", "encurtador.com.br", "encurta.net", "tiny.cc", "rb.gy",
            "s.id", "t.ly", "bit.do", "tiny.one", "short.io", "shorte.st", "adf.ly", "ouo.io", "u.to",
            "x.co", "lnkd.in", "surl.li", "shre.ink", "abre.ai", "encr.pw", "qrco.de", "l.ead.me",
            "chilp.it", "clck.ru", "soo.gd", "tr.im", "urlz.fr", "linkr.bio", "1url.com.br", "migre.me",
        )

        val EXECUTABLE_EXTENSIONS = listOf(
            "apk", "xapk", "apks", "aab", "exe", "scr", "msi", "bat", "cmd", "pif", "vbs", "vbe",
            "jse", "wsf", "hta", "jar", "ps1", "lnk", "dll", "cpl", "msix", "appx", "dmg", "pkg",
        )

        val ARCHIVE_EXTENSIONS = listOf("zip", "rar", "7z", "iso", "img", "cab", "gz", "tar", "arj", "ace")

        val FREE_TLDS = setOf("tk", "ml", "ga", "cf", "gq")

        /** Palavras reais parecidas com marcas, que não devem ser tratadas como erro de digitação. */
        val TYPO_SKIP = setOf(
            "shoppe", "paypay", "telegraf", "twister", "finance", "correio", "americana", "goggles",
            "spotty", "discos", "neonbank",
        )

        val RISKY_TLDS = setOf(
            "zip", "mov", "xyz", "top", "click", "icu", "buzz", "rest", "cfd", "sbs", "cyou", "monster",
            "quest", "lol", "online", "site", "website", "shop", "store", "fun", "space", "club", "work",
            "support", "help", "live", "vip", "bond", "today", "pw", "su", "ws", "cc",
        )

        val REDIRECT_PARAMS = setOf(
            "url", "u", "q", "redirect", "redirect_url", "redirect_uri", "redirecturl", "redir", "next", "target",
            "dest", "destination", "continue", "link", "goto", "go", "r", "out", "to", "returnurl", "return",
            "return_to", "returnto", "forward", "rurl", "src", "site", "page",
        )

        /** Palavras procuradas no nome do site (sem acentos e sem hífen). */
        val SUSPICIOUS_WORDS = listOf(
            "login", "signin", "logon", "seguranca", "security", "secure", "verifica", "verify", "validar",
            "validacao", "atualiza", "update", "desbloque", "bloquead", "suspens", "senha", "password",
            "premio", "premiad", "premiacao", "resgat", "sorteio", "regulariza", "pendencia", "suporte", "support",
            "confirma", "acesso", "cadastro", "recadastr", "restitui", "indeniza", "beneficio", "auxilio",
            "saque", "cashback", "promocao", "oferta", "desconto", "cupom", "boleto", "fatura", "segundavia",
            "2via", "rastreio", "rastreamento", "encomenda", "taxa", "pix", "token", "wallet", "carteira",
            "airdrop", "bonus", "gratis", "recompensa", "reembolso", "protecao", "antifraude",
        )

        /** Distância de edição com troca de letras vizinhas (Damerau-Levenshtein restrita). */
        fun osaDistance(a: String, b: String): Int {
            val n = a.length
            val m = b.length
            val d = Array(n + 1) { IntArray(m + 1) }
            for (i in 0..n) d[i][0] = i
            for (j in 0..m) d[0][j] = j
            for (i in 1..n) {
                for (j in 1..m) {
                    val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                    var v = minOf(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
                    if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) {
                        v = minOf(v, d[i - 2][j - 2] + 1)
                    }
                    d[i][j] = v
                }
            }
            return d[n][m]
        }
    }
}
