package com.example.klin_kercher.core.url

import java.text.Normalizer

/**
 * Letras que se parecem com as nossas. Golpistas registram domínios como "nubаnk.com"
 * com um "а" cirílico, que na tela é idêntico ao "a" latino.
 */
object Confusables {

    /** Caracteres de outros alfabetos → letra latina parecida. */
    private val MAP: Map<Char, Char> = buildMap {
        // Cirílico
        put('а', 'a'); put('в', 'b'); put('е', 'e'); put('ё', 'e'); put('о', 'o'); put('р', 'p')
        put('с', 'c'); put('у', 'y'); put('х', 'x'); put('к', 'k'); put('м', 'm'); put('н', 'h')
        put('т', 't'); put('і', 'i'); put('ї', 'i'); put('ј', 'j'); put('ѕ', 's'); put('һ', 'h')
        put('ԁ', 'd'); put('ԛ', 'q'); put('ԝ', 'w'); put('ӏ', 'l'); put('ү', 'y'); put('ѵ', 'v')
        put('ɡ', 'g'); put('ց', 'g'); put('ո', 'n'); put('ս', 'u'); put('օ', 'o'); put('հ', 'h')
        // Grego
        put('α', 'a'); put('β', 'b'); put('ε', 'e'); put('η', 'n'); put('ι', 'i'); put('κ', 'k')
        put('ν', 'v'); put('ο', 'o'); put('ρ', 'p'); put('τ', 't'); put('υ', 'u'); put('χ', 'x')
        put('ϲ', 'c'); put('ω', 'w'); put('γ', 'y')
        // Latim estendido que não se decompõe com NFKD
        put('ı', 'i'); put('ł', 'l'); put('ɑ', 'a'); put('ø', 'o'); put('đ', 'd'); put('ħ', 'h')
        put('ŀ', 'l'); put('ƅ', 'b'); put('ɩ', 'i'); put('ʟ', 'l'); put('ɢ', 'g'); put('ʜ', 'h')
        put('ꞵ', 'b'); put('ß', 's')
    }

    /**
     * Converte para a "silhueta" latina: remove acentos (ã → a), converte letras largas
     * (ｇｏｏｇｌｅ → google) e troca letras de outros alfabetos pelas latinas parecidas.
     */
    fun latinSkeleton(s: String): String {
        val decomposed = Normalizer.normalize(s, Normalizer.Form.NFKD)
        val sb = StringBuilder(decomposed.length)
        for (ch in decomposed) {
            val type = Character.getType(ch)
            if (type == Character.NON_SPACING_MARK.toInt() || type == Character.COMBINING_SPACING_MARK.toInt() ||
                type == Character.ENCLOSING_MARK.toInt()
            ) continue
            val lower = ch.lowercaseChar()
            sb.append(MAP[lower] ?: lower)
        }
        return sb.toString()
    }

    /**
     * Variações de "leet" (números e símbolos no lugar de letras): g00gle → google, paypa1 → paypal.
     * O "1" pode ser "l" ou "i", então devolvemos as duas versões.
     */
    fun leetVariants(s: String): Set<String> {
        val base = StringBuilder()
        for (c in s) {
            base.append(
                when (c) {
                    '0' -> 'o'; '3' -> 'e'; '4' -> 'a'; '5' -> 's'; '7' -> 't'; '8' -> 'b'
                    '@' -> 'a'; '$' -> 's'; '|' -> 'l'
                    else -> c
                }
            )
        }
        val b = base.toString()
        val out = LinkedHashSet<String>()
        for (v in listOf(b.replace('1', 'l'), b.replace('1', 'i'))) {
            out.add(v)
            out.add(v.replace("rn", "m").replace("vv", "w"))
        }
        out.remove(s)
        return out
    }

    /** Alfabetos usados num texto (ignora números, hífen e pontuação). */
    fun scripts(s: String): Set<Character.UnicodeScript> {
        val out = HashSet<Character.UnicodeScript>()
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            val sc = Character.UnicodeScript.of(cp)
            if (sc != Character.UnicodeScript.COMMON && sc != Character.UnicodeScript.INHERITED) out.add(sc)
            i += Character.charCount(cp)
        }
        return out
    }

    fun hasNonAscii(s: String): Boolean = s.any { it.code > 127 }
}
