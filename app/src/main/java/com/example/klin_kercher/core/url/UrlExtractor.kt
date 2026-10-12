package com.example.klin_kercher.core.url

/**
 * Encontra links dentro de um texto qualquer, como uma mensagem compartilhada do WhatsApp
 * ("Seu pacote foi taxado, pague em https://…").
 */
object UrlExtractor {

    private val EXPLICIT = Regex("""(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>"'`]+""")

    /** Terminações aceitas para endereços escritos sem http:// nem www. */
    private val BARE_TLDS = setOf(
        "com", "br", "net", "org", "info", "biz", "io", "co", "me", "app", "dev", "xyz", "top", "shop", "store",
        "online", "site", "website", "click", "link", "live", "ly", "gl", "to", "cc", "ws", "tk", "ml", "ga", "cf", "gq",
        "icu", "buzz", "vip", "club", "fun", "space", "pw", "ru", "cn", "us", "uk", "pt", "es", "de", "fr", "it", "in",
        "zip", "mov", "sbs", "cfd", "rest", "bond", "today", "page", "gov", "edu", "tv", "fm", "ai", "gg", "id", "at",
    )
    private val BARE = Regex("""(?i)(?<![\w@./-])(?:[a-z0-9\u00a1-\uffff](?:[a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?\.)+([a-z\u00a1-\uffff]{2,24})(?::\d{2,5})?(?:/[^\s<>"'`]*)?""")
    private val TRAILING = charArrayOf('.', ',', ';', ':', '!', '?', ']', '}', '\'', '"', '»', '”', '>', '*')

    /** Retorna até [limit] links, na ordem em que aparecem e sem repetição. */
    fun extract(text: String, limit: Int = 5): List<String> {
        val found = LinkedHashMap<Int, String>()
        for (m in EXPLICIT.findAll(text)) found[m.range.first] = clean(m.value)
        for (m in BARE.findAll(text)) {
            if (found.keys.any { start -> m.range.first in start until start + found[start]!!.length }) continue
            val tld = m.groupValues[1].lowercase()
            if (tld !in BARE_TLDS && !tld.any { it.code > 127 }) continue
            found[m.range.first] = clean(m.value)
        }
        return found.toSortedMap().values
            .map { it.replaceFirst(Regex("(?i)^hxxp"), "http") }
            .filter { it.length > 3 }
            .distinct()
            .take(limit)
    }

    private fun clean(s: String): String {
        var out = s.trimEnd(*TRAILING)
        // parêntese final só faz parte do link se houver um de abertura
        while (out.endsWith(")") && out.count { it == '(' } < out.count { it == ')' }) out = out.dropLast(1)
        return out
    }
}
