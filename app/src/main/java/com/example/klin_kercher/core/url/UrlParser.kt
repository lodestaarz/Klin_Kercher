package com.example.klin_kercher.core.url

import java.net.IDN

/**
 * Endereço já separado em partes.
 * [host] fica sempre em ASCII minúsculo (punycode, se for internacional);
 * [unicodeHost] é como o usuário veria no navegador.
 */
data class ParsedUrl(
    val original: String,
    val scheme: String,
    val schemeAssumed: Boolean,
    val userInfo: String?,
    val host: String,
    val unicodeHost: String,
    val port: Int?,
    val path: String,
    val query: String?,
    val fragment: String?,
    /** O host continha %xx (codificação usada para esconder o nome). */
    val hostWasPercentEncoded: Boolean,
    /** Preenchido quando o host é um IPv4 (em qualquer formato). */
    val ipv4: DomainUtils.Ipv4?,
) {
    val isIpv6: Boolean get() = host.startsWith("[")

    /** Host usado nas consultas: IPs disfarçados viram a forma normal (192.168.0.1). */
    val canonicalHost: String get() = ipv4?.canonical ?: host

    val registrableDomain: String get() = DomainUtils.registrableDomain(canonicalHost)

    /** Endereço normalizado, mostrado na tela. */
    fun display(): String = buildString {
        append(scheme).append("://")
        append(unicodeHost)
        if (port != null) append(':').append(port)
        append(path.ifEmpty { "/" })
        if (!query.isNullOrEmpty()) append('?').append(query)
    }

    /**
     * Chaves usadas para comparar com listas de endereços (URLhaus, OpenPhish).
     * Ignoram o esquema (http/https), o fragmento (#) e a barra final.
     */
    fun lookupKeys(): List<String> {
        val hostPort = canonicalHost + (if (port != null) ":$port" else "")
        val p = path.ifEmpty { "/" }
        val keys = LinkedHashSet<String>()
        val q = if (query.isNullOrEmpty()) "" else "?$query"
        keys.add(hostPort + p + q)
        if (p != "/") {
            val altPath = if (p.endsWith("/")) p.dropLast(1) else "$p/"
            keys.add(hostPort + altPath + q)
        }
        return keys.toList()
    }
}

object UrlParser {

    private val SCHEME_RE = Regex("^([a-zA-Z][a-zA-Z0-9+.\\-]*):")

    /** Esquemas que não são páginas da web e por si só merecem atenção. */
    val NON_WEB_SCHEMES = setOf("javascript", "data", "vbscript", "file", "intent", "content", "blob")

    /** Esquemas de outros apps (e-mail, telefone…), que não são sites. */
    val OTHER_APP_SCHEMES = setOf("mailto", "tel", "sms", "smsto", "geo", "market", "whatsapp", "tg", "about")

    /** Esquema sem "//" (javascript:, data:…). Retorna o esquema em minúsculas ou null. */
    fun nonWebScheme(input: String): String? {
        val m = SCHEME_RE.find(input.trim()) ?: return null
        val s = m.groupValues[1].lowercase()
        return if (s in NON_WEB_SCHEMES) s else null
    }

    /**
     * Lê um endereço do jeito tolerante dos navegadores: aceita sem "http://",
     * trata "\" como "/", usa o último "@" para separar usuário de host etc.
     * Retorna null se não houver um host utilizável.
     */
    fun parse(rawInput: String): ParsedUrl? {
        var input = rawInput.trim().trim('<', '>', '"', '\'', '`').trim()
        if (input.isEmpty()) return null
        // remove espaços e quebras invisíveis que navegadores também ignoram
        input = input.filterNot { it == '\n' || it == '\r' || it == '\t' }
        input = input.replace('\\', '/')

        var scheme = "http"
        var schemeAssumed = true
        var rest = input
        val schemeMatch = SCHEME_RE.find(input)
        if (schemeMatch != null) {
            val s = schemeMatch.groupValues[1].lowercase()
            val afterColon = input.substring(schemeMatch.range.last + 1)
            if (afterColon.startsWith("//")) {
                scheme = s; schemeAssumed = false
                rest = afterColon.trimStart('/')
            } else if (s == "http" || s == "https") {
                // "https:exemplo.com" — navegadores corrigem
                scheme = s; schemeAssumed = false
                rest = afterColon.trimStart('/')
            } else if (s in NON_WEB_SCHEMES || s in OTHER_APP_SCHEMES) {
                return null
            }
            // senão é algo como "exemplo.com:8080/x" — o "esquema" era o host
        } else if (rest.startsWith("//")) {
            rest = rest.trimStart('/')
        }

        val authorityEnd = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }.let { if (it < 0) rest.length else it }
        val authority = rest.substring(0, authorityEnd)
        val afterAuthority = rest.substring(authorityEnd)

        var userInfo: String? = null
        var hostPort = authority
        val at = authority.lastIndexOf('@')
        if (at >= 0) {
            userInfo = authority.substring(0, at)
            hostPort = authority.substring(at + 1)
        }

        var hostRaw: String
        var port: Int? = null
        if (hostPort.startsWith("[")) {
            val close = hostPort.indexOf(']')
            if (close < 0) return null
            hostRaw = hostPort.substring(0, close + 1)
            val after = hostPort.substring(close + 1)
            if (after.startsWith(":")) port = after.substring(1).toIntOrNull()
        } else {
            val colon = hostPort.lastIndexOf(':')
            if (colon >= 0) {
                val p = hostPort.substring(colon + 1)
                hostRaw = hostPort.substring(0, colon)
                if (p.isNotEmpty()) port = p.toIntOrNull() ?: return null
            } else {
                hostRaw = hostPort
            }
        }

        val percentEncoded = hostRaw.contains('%')
        if (percentEncoded) hostRaw = percentDecode(hostRaw)
        // pontos "largos" usados em alguns alfabetos são aceitos como separador
        hostRaw = hostRaw.replace('。', '.').replace('．', '.').replace('｡', '.')
        hostRaw = hostRaw.trimEnd('.').lowercase()
        if (hostRaw.isEmpty() || hostRaw.any { it.isWhitespace() || it == '<' || it == '>' || it == '"' }) return null

        val asciiHost: String
        val unicodeHost: String
        if (hostRaw.startsWith("[")) {
            asciiHost = hostRaw; unicodeHost = hostRaw
        } else {
            asciiHost = try {
                IDN.toASCII(hostRaw, IDN.ALLOW_UNASSIGNED).lowercase()
            } catch (e: IllegalArgumentException) {
                if (hostRaw.all { it.code < 128 }) hostRaw else return null
            }
            unicodeHost = try {
                IDN.toUnicode(asciiHost, IDN.ALLOW_UNASSIGNED).lowercase()
            } catch (e: IllegalArgumentException) {
                hostRaw
            }
        }
        if (!asciiHost.startsWith("[") && !asciiHost.all { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' }) return null

        var path = afterAuthority
        var fragment: String? = null
        var query: String? = null
        val hash = path.indexOf('#')
        if (hash >= 0) { fragment = path.substring(hash + 1); path = path.substring(0, hash) }
        val qm = path.indexOf('?')
        if (qm >= 0) { query = path.substring(qm + 1); path = path.substring(0, qm) }

        val ipv4 = if (asciiHost.startsWith("[")) null else DomainUtils.parseIpv4(asciiHost)
        // sem esquema e sem ponto (ex.: "teste") não é um endereço
        if (schemeAssumed && !asciiHost.contains('.') && ipv4 == null && !asciiHost.startsWith("[")) return null

        return ParsedUrl(
            original = rawInput.trim(),
            scheme = scheme,
            schemeAssumed = schemeAssumed,
            userInfo = userInfo,
            host = asciiHost,
            unicodeHost = unicodeHost,
            port = port,
            path = path,
            query = query,
            fragment = fragment,
            hostWasPercentEncoded = percentEncoded,
            ipv4 = ipv4,
        )
    }

    /** Decodifica %xx como UTF-8, sem lançar erro em sequências inválidas. */
    fun percentDecode(s: String): String {
        if (!s.contains('%') && !s.contains('+')) return s
        val bytes = java.io.ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '%' && i + 2 < s.length) {
                val hex = s.substring(i + 1, i + 3)
                val v = hex.toIntOrNull(16)
                if (v != null) { bytes.write(v); i += 3; continue }
            }
            if (c == '+') { bytes.write(' '.code); i++; continue }
            val enc = c.toString().toByteArray(Charsets.UTF_8)
            bytes.write(enc, 0, enc.size)
            i++
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    /** Pares chave=valor da query, com valores decodificados. */
    fun queryParams(query: String?): List<Pair<String, String>> {
        if (query.isNullOrEmpty()) return emptyList()
        return query.split('&', ';').filter { it.isNotEmpty() }.map {
            val eq = it.indexOf('=')
            if (eq < 0) percentDecode(it) to "" else percentDecode(it.substring(0, eq)) to percentDecode(it.substring(eq + 1))
        }
    }
}
