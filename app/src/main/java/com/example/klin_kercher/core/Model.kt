package com.example.klin_kercher.core

/**
 * Tipos compartilhados pelos analisadores de links e de arquivos.
 * Este pacote (core) é Kotlin puro: não usa nenhuma API do Android,
 * por isso pode ser testado com JUnit comum (app/src/test).
 */

/** Gravidade de um sinal encontrado. O peso entra na soma que decide o veredito. */
enum class Severity(val weight: Int, val label: String) {
    INFO(0, "Informação"),
    BAIXO(1, "Atenção"),
    MEDIO(3, "Suspeito"),
    ALTO(6, "Perigoso"),
    CRITICO(10, "Ameaça conhecida"),
}

/**
 * Um sinal encontrado durante a análise.
 * @param code identificador estável (útil em testes e para traduções futuras)
 * @param title frase curta mostrada em destaque
 * @param detail explicação em linguagem simples
 */
data class Finding(
    val code: String,
    val severity: Severity,
    val title: String,
    val detail: String,
)

enum class Verdict(val label: String, val summary: String) {
    SEM_SINAIS(
        "Nenhum sinal de risco",
        "Não encontramos sinais de golpe. A análise é feita no aparelho e não garante 100% de segurança.",
    ),
    SUSPEITO(
        "Suspeito",
        "Há sinais comuns em golpes. Só continue se tiver certeza de onde isso veio.",
    ),
    PERIGOSO(
        "Perigoso",
        "Fortes sinais de golpe ou ameaça conhecida. Não abra, não instale e não informe dados.",
    );

    companion object {
        fun from(findings: List<Finding>): Verdict {
            if (findings.any { it.severity >= Severity.ALTO }) return PERIGOSO
            val score = findings.sumOf { it.severity.weight }
            return when {
                score >= 9 -> PERIGOSO
                score >= 2 || findings.any { it.severity == Severity.MEDIO } -> SUSPEITO
                else -> SEM_SINAIS
            }
        }

        fun worst(a: Verdict, b: Verdict): Verdict = if (a.ordinal >= b.ordinal) a else b
    }
}

/** Resultado de uma consulta à base local de ameaças. */
data class ThreatMatch(
    val kind: Kind,
    /** O valor que bateu (domínio, endereço ou hash). */
    val value: String,
    /** Nome da ameaça, quando a lista informa (ex.: família do malware). */
    val label: String? = null,
    /** De onde veio o registro (ex.: "MalwareBazaar", "importado"). */
    val source: String? = null,
) {
    enum class Kind { DOMAIN, URL, HASH }
}

/** Hashes de um arquivo, sempre em hexadecimal minúsculo. */
data class FileHashes(val sha256: String, val sha1: String, val md5: String)

/**
 * Consulta à base local. A implementação real (SQLite) fica em data/ThreatDatabase.kt;
 * os testes usam [InMemoryThreatLookup].
 */
interface ThreatLookup {
    /** @param hosts o host analisado e seus domínios-pai, do mais específico ao mais geral. */
    fun matchDomain(hosts: List<String>): ThreatMatch?

    /** @param urlKeys chaves geradas por [com.example.klin_kercher.core.url.ParsedUrl.lookupKeys]. */
    fun matchUrl(urlKeys: List<String>): ThreatMatch?

    fun matchHash(hashes: FileHashes): ThreatMatch?
}

/** Base em memória, usada nos testes e como reserva enquanto a base SQLite carrega. */
class InMemoryThreatLookup(
    domains: Map<String, String?> = emptyMap(),
    urls: Map<String, String?> = emptyMap(),
    hashes: Map<String, String?> = emptyMap(),
    private val source: String = "lista local",
) : ThreatLookup {
    private val domains = domains.mapKeys { it.key.lowercase() }
    private val urls = urls.toMap()
    private val hashes = hashes.mapKeys { it.key.lowercase() }

    override fun matchDomain(hosts: List<String>): ThreatMatch? {
        for (h in hosts) {
            if (domains.containsKey(h)) return ThreatMatch(ThreatMatch.Kind.DOMAIN, h, domains[h], source)
        }
        return null
    }

    override fun matchUrl(urlKeys: List<String>): ThreatMatch? {
        for (k in urlKeys) {
            if (urls.containsKey(k)) return ThreatMatch(ThreatMatch.Kind.URL, k, urls[k], source)
        }
        return null
    }

    override fun matchHash(hashes: FileHashes): ThreatMatch? {
        for (h in listOf(hashes.sha256, hashes.sha1, hashes.md5)) {
            if (this.hashes.containsKey(h)) return ThreatMatch(ThreatMatch.Kind.HASH, h, this.hashes[h], source)
        }
        return null
    }

    companion object {
        val EMPTY = InMemoryThreatLookup()
    }
}
