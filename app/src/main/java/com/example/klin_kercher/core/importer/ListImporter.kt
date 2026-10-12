package com.example.klin_kercher.core.importer

import com.example.klin_kercher.core.url.DomainUtils
import com.example.klin_kercher.core.url.UrlParser
import java.io.BufferedReader

/** Registro lido de uma lista. [label] é o nome da ameaça, quando a lista informa. */
data class HashEntry(val hash: String, val label: String?)
data class DomainEntry(val domain: String, val label: String?)
data class UrlEntry(val key: String, val label: String?)

data class ImportResult(
    val hashes: List<HashEntry> = emptyList(),
    val domains: List<DomainEntry> = emptyList(),
    val urls: List<UrlEntry> = emptyList(),
    /** Linhas com conteúdo que não puderam ser aproveitadas. */
    val skippedLines: Int = 0,
) {
    val total: Int get() = hashes.size + domains.size + urls.size
}

/**
 * Lê listas de ameaças nos formatos mais comuns:
 *
 * Hashes — um por linha, com ou sem comentários (#, //, ;), ou CSV
 * (ex.: exportação do MalwareBazaar). Aceita SHA-256, SHA-1 e MD5.
 *
 * Domínios e endereços — um por linha, arquivo hosts ("0.0.0.0 site.com"),
 * regras AdBlock ("||site.com^"), endereços completos (URLhaus, OpenPhish) ou CSV.
 *
 * Endereços completos viram uma regra para o endereço exato e, quando o site não é
 * uma plataforma compartilhada (Google Drive, GitHub…), também uma regra para o site inteiro.
 */
object ListImporter {

    private val HEX_TOKEN = Regex("(?i)(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])")
    private val DOMAIN_RE = Regex("^(?=.{3,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
    private val IGNORED_HOSTS = setOf(
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "0.0.0.0", "127.0.0.1", "255.255.255.255", "::1",
    )

    /**
     * Sites onde qualquer pessoa hospeda arquivos. Um link malicioso nesses sites
     * não torna o site inteiro malicioso, então só o endereço exato é bloqueado.
     */
    val SHARED_PLATFORMS = setOf(
        "google.com", "googleusercontent.com", "googleapis.com", "github.com", "githubusercontent.com",
        "gitlab.com", "bitbucket.org", "dropbox.com", "dropboxusercontent.com", "onedrive.live.com", "1drv.ms",
        "live.com", "sharepoint.com", "microsoft.com", "mega.nz", "mediafire.com", "discord.com", "discordapp.com",
        "discordapp.net", "t.me", "telegram.org", "facebook.com", "instagram.com", "whatsapp.com", "twitter.com",
        "x.com", "youtube.com", "amazonaws.com", "cloudfront.net", "azureedge.net", "windows.net", "wetransfer.com",
        "we.tl", "pastebin.com", "archive.org", "sourceforge.net", "linkedin.com", "notion.so", "notion.site",
        "canva.com", "figma.com", "forms.gle", "docs.google.com", "drive.google.com", "sites.google.com",
        "firebasestorage.googleapis.com", "r2.dev", "ipfs.io", "cloudflare-ipfs.com", "4shared.com", "anonfiles.com",
        "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rebrand.ly", "wixsite.com", "weebly.com", "blogspot.com",
        "wordpress.com", "yahoo.com", "outlook.com", "office.com", "apple.com", "icloud.com", "adobe.com",
        "transfer.sh", "catbox.moe", "imgur.com", "goo.gl", "tiny.cc", "ow.ly", "linktr.ee",
    )

    // ------------------------------------------------------------------ hashes

    fun parseHashes(reader: BufferedReader, maxEntries: Int = 2_000_000): ImportResult {
        val out = ArrayList<HashEntry>()
        val seen = HashSet<String>()
        var skipped = 0
        var signatureCol = -1
        // Em CSV com cabeçalho, só as colunas de hash são lidas (evita pegar "imphash" e afins).
        var hashCols: List<Int> = emptyList()
        var csvHeaderChecked = false

        fun readHeader(header: String) {
            val cols = csvColumns(header).map { it.lowercase() }
            signatureCol = cols.indexOfFirst { it == "signature" || it == "malware" || it == "family" || it == "threat" }
            hashCols = cols.withIndex()
                .filter { (_, c) -> (c.contains("sha256") || c.contains("sha1") || c.contains("md5") || c == "hash") && !c.contains("imphash") }
                .map { it.index }
            csvHeaderChecked = true
        }

        reader.lineSequence().forEach { raw ->
            if (out.size >= maxEntries) return@forEach
            val line = raw.trim().removePrefix("\uFEFF")
            if (line.isEmpty()) return@forEach
            if (isComment(line)) {
                // cabeçalho CSV comentado, como no MalwareBazaar: # "first_seen_utc","sha256_hash",...,"signature"
                val h = line.trimStart('#', '/', ';', '!', ' ')
                if (!csvHeaderChecked && h.contains(',') && Regex("(?i)sha256|sha1|md5|hash").containsMatchIn(h)) readHeader(h)
                return@forEach
            }
            if (!csvHeaderChecked && line.contains(',') && !HEX_TOKEN.containsMatchIn(line)) {
                readHeader(line)
                return@forEach
            }
            val cols = if (line.contains(',') || line.contains('"')) csvColumns(line) else null
            val source = if (cols != null && hashCols.isNotEmpty()) hashCols.mapNotNull { cols.getOrNull(it) }.joinToString(" ") else line
            val tokens = HEX_TOKEN.findAll(source).map { it.value.lowercase() }.toList()
            if (tokens.isEmpty()) { skipped++; return@forEach }
            val label = if (cols != null && signatureCol >= 0) cols.getOrNull(signatureCol)?.takeIf { it.isNotBlank() && it != "n/a" } else null
            for (t in tokens) if (seen.add(t)) out.add(HashEntry(t, label))
        }
        return ImportResult(hashes = out, skippedLines = skipped)
    }

    // ---------------------------------------------------------- domínios e URLs

    fun parseDomainsAndUrls(reader: BufferedReader, maxEntries: Int = 2_000_000): ImportResult {
        val domains = LinkedHashMap<String, DomainEntry>()
        val urls = LinkedHashMap<String, UrlEntry>()
        var skipped = 0
        var threatCol = -1
        var urlCol = -1
        reader.lineSequence().forEach { raw ->
            if (domains.size + urls.size >= maxEntries) return@forEach
            var line = raw.trim().removePrefix("\uFEFF")
            if (line.isEmpty()) return@forEach
            if (line.startsWith("#") || line.startsWith("!") || line.startsWith("//") || line.startsWith(";") || line.startsWith("[")) {
                // cabeçalho CSV comentado (URLhaus): # id,dateadded,url,url_status,last_online,threat,tags,...
                val h = line.trimStart('#', ' ')
                if (h.contains(',') && h.contains("url", true)) {
                    val cols = csvColumns(h)
                    urlCol = cols.indexOfFirst { it.equals("url", true) }
                    threatCol = cols.indexOfFirst { it.equals("threat", true) }
                }
                return@forEach
            }
            // AdBlock: exceções (@@) não são bloqueios
            if (line.startsWith("@@")) return@forEach

            val candidates: List<String>
            var label: String? = null
            if (line.contains(',') || line.contains('"')) {
                val cols = csvColumns(line)
                if (urlCol >= 0 && cols.size > urlCol) {
                    candidates = listOf(cols[urlCol])
                    if (threatCol >= 0) label = cols.getOrNull(threatCol)?.takeIf { it.isNotBlank() }
                } else {
                    candidates = cols.filter { it.contains('.') }
                }
            } else {
                // remove comentário no fim da linha
                line = line.substringBefore(" #").substringBefore("\t#").trim()
                val parts = line.split(Regex("\\s+"))
                candidates = if (parts.size >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::" || parts[0] == "::1")) {
                    parts.drop(1) // formato hosts
                } else listOf(parts[0])
            }

            var used = false
            for (c in candidates) {
                when (val item = classify(c)) {
                    is Classified.Domain -> {
                        if (item.domain !in IGNORED_HOSTS) {
                            domains.putIfAbsent(item.domain, DomainEntry(item.domain, label)); used = true
                        }
                    }
                    is Classified.Url -> {
                        urls.putIfAbsent(item.key, UrlEntry(item.key, label)); used = true
                        if (item.host !in IGNORED_HOSTS && !isSharedPlatform(item.host)) {
                            domains.putIfAbsent(item.host, DomainEntry(item.host, label))
                        }
                    }
                    null -> Unit
                }
            }
            if (!used) skipped++
        }
        return ImportResult(domains = domains.values.toList(), urls = urls.values.toList(), skippedLines = skipped)
    }

    private sealed class Classified {
        data class Domain(val domain: String) : Classified()
        data class Url(val key: String, val host: String) : Classified()
    }

    private fun classify(raw: String): Classified? {
        var s = raw.trim().trim('"', '\'')
        if (s.isEmpty()) return null
        // AdBlock: ||site.com^ ou ||site.com^$third-party
        if (s.startsWith("||")) {
            s = s.removePrefix("||").substringBefore('^').substringBefore('$').substringBefore('/')
            return normalizeDomain(s)?.let { Classified.Domain(it) }
        }
        if (s.startsWith("|")) s = s.removePrefix("|")
        val lower = s.lowercase()
        val hasScheme = lower.startsWith("http://") || lower.startsWith("https://") || lower.startsWith("hxxp")
        val hasPath = s.indexOfAny(charArrayOf('/', '?')) > 0
        if (!hasScheme && !hasPath) {
            s = s.removePrefix("*.").removePrefix(".")
            return normalizeDomain(s)?.let { Classified.Domain(it) }
        }
        val p = UrlParser.parse(s.replaceFirst(Regex("(?i)^hxxp"), "http")) ?: return null
        val pathIsRoot = p.path.isEmpty() || p.path == "/"
        if (pathIsRoot && p.query.isNullOrEmpty()) {
            return normalizeDomain(p.canonicalHost)?.let { Classified.Domain(it) }
        }
        return Classified.Url(p.lookupKeys().first(), p.canonicalHost)
    }

    /** Valida e normaliza um nome de domínio ou IPv4. Retorna null se for inválido. */
    fun normalizeDomain(raw: String): String? {
        var d = raw.trim().trimEnd('.').lowercase()
        if (d.isEmpty() || d.length > 253) return null
        DomainUtils.parseIpv4(d)?.let { return if (!it.disguised) it.canonical else null }
        if (d.any { it.code > 127 }) {
            d = try { java.net.IDN.toASCII(d).lowercase() } catch (e: IllegalArgumentException) { return null }
        }
        return if (DOMAIN_RE.matches(d)) d else null
    }

    fun isSharedPlatform(host: String): Boolean =
        SHARED_PLATFORMS.any { DomainUtils.isSameOrSubdomain(host, it) }

    private fun isComment(line: String) =
        line.startsWith("#") || line.startsWith("//") || line.startsWith(";") || line.startsWith("!")

    /** Divide uma linha CSV respeitando aspas. */
    fun csvColumns(line: String): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val c = line[i]
            when {
                c == '"' && inQuotes && i + 1 < line.length && line[i + 1] == '"' -> { sb.append('"'); i++ }
                c == '"' -> inQuotes = !inQuotes
                c == ',' && !inQuotes -> { out.add(sb.toString().trim()); sb.setLength(0) }
                else -> sb.append(c)
            }
            i++
        }
        out.add(sb.toString().trim())
        return out
    }
}
