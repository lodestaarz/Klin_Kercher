package com.example.klin_kercher.data

import android.content.Context
import com.example.klin_kercher.core.importer.ImportResult
import com.example.klin_kercher.core.importer.ListImporter
import java.util.Properties

/**
 * Listas que vêm dentro do APK, na pasta app/src/main/assets/base/.
 *
 * Convenção de nomes:
 *   hashes_*.txt   → listas de hashes (SHA-256, SHA-1 ou MD5)
 *   dominios_*.txt → listas de domínios (uma por linha, hosts, AdBlock)
 *   urls_*.txt     → listas de endereços completos (URLhaus, OpenPhish)
 *
 * O arquivo base.properties traz a versão e o nome de cada fonte. Quando a versão muda
 * (ao rodar tools/atualizar_base.py e gerar um novo APK), a parte embutida da base é recarregada.
 */
class BundledBase(private val context: Context) {

    data class Info(val version: String, val date: String?, val sources: Map<String, String>)

    fun info(): Info {
        val props = Properties()
        try {
            context.assets.open("$DIR/base.properties").use { props.load(it.reader(Charsets.UTF_8)) }
        } catch (e: java.io.IOException) {
            return Info("0", null, emptyMap())
        }
        val sources = props.stringPropertyNames()
            .filter { it.startsWith("fonte.") }
            .associate { it.removePrefix("fonte.") to props.getProperty(it) }
        return Info(props.getProperty("versao", "0"), props.getProperty("gerado_em"), sources)
    }

    /** Recarrega a parte embutida da base se a versão do APK for diferente da que está no banco. */
    fun ensureLoaded(db: ThreatDatabase, force: Boolean = false): Boolean {
        val info = info()
        if (!force && db.getMeta(ThreatDatabase.META_BUNDLED_VERSION) == info.version) return false
        db.deleteByOrigin(ThreatDatabase.ORIGIN_BUNDLED)
        val files = context.assets.list(DIR).orEmpty().filter { it.endsWith(".txt") || it.endsWith(".csv") }.sorted()
        for (file in files) {
            val result = parse(file) ?: continue
            val source = info.sources[file] ?: file.substringBeforeLast('.')
            db.insert(result, source, ThreatDatabase.ORIGIN_BUNDLED)
        }
        db.setMeta(ThreatDatabase.META_BUNDLED_VERSION, info.version)
        db.setMeta(ThreatDatabase.META_BUNDLED_DATE, info.date)
        return true
    }

    private fun parse(file: String): ImportResult? {
        val reader = { context.assets.open("$DIR/$file").bufferedReader(Charsets.UTF_8) }
        return when {
            file.startsWith("hashes_") -> reader().use { ListImporter.parseHashes(it) }
            file.startsWith("dominios_") || file.startsWith("urls_") -> reader().use { ListImporter.parseDomainsAndUrls(it) }
            else -> null
        }
    }

    companion object {
        const val DIR = "base"
    }
}
