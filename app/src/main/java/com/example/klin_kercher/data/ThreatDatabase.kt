package com.example.klin_kercher.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.example.klin_kercher.core.FileHashes
import com.example.klin_kercher.core.ThreatLookup
import com.example.klin_kercher.core.ThreatMatch
import com.example.klin_kercher.core.importer.ImportResult

/**
 * Base local de ameaças (SQLite), guardada só no aparelho.
 *
 * Cada registro tem uma origem:
 *  - [ORIGIN_BUNDLED]: veio embutido no APK (pasta assets/base, gerada por tools/atualizar_base.py);
 *  - [ORIGIN_IMPORTED]: importado pelo usuário na tela "Base local".
 */
class ThreatDatabase private constructor(context: Context) :
    SQLiteOpenHelper(context.applicationContext, DB_NAME, null, DB_VERSION), ThreatLookup {

    init {
        setWriteAheadLoggingEnabled(true)
    }

    data class Stats(
        val hashes: Int,
        val domains: Int,
        val urls: Int,
        val importedHashes: Int,
        val importedDomains: Int,
        val importedUrls: Int,
        val bundledVersion: String?,
        val bundledDate: String?,
    ) {
        val total: Int get() = hashes + domains + urls
        val imported: Int get() = importedHashes + importedDomains + importedUrls
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE hashes (value TEXT PRIMARY KEY NOT NULL, label TEXT, source TEXT, origin INTEGER NOT NULL) WITHOUT ROWID")
        db.execSQL("CREATE TABLE domains (value TEXT PRIMARY KEY NOT NULL, label TEXT, source TEXT, origin INTEGER NOT NULL) WITHOUT ROWID")
        db.execSQL("CREATE TABLE urls (value TEXT PRIMARY KEY NOT NULL, label TEXT, source TEXT, origin INTEGER NOT NULL) WITHOUT ROWID")
        db.execSQL("CREATE TABLE meta (key TEXT PRIMARY KEY NOT NULL, value TEXT) WITHOUT ROWID")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        // Primeira versão do esquema: nada a migrar ainda.
    }

    // ------------------------------------------------------------- consultas

    override fun matchDomain(hosts: List<String>): ThreatMatch? =
        matchIn("domains", hosts, ThreatMatch.Kind.DOMAIN)

    override fun matchUrl(urlKeys: List<String>): ThreatMatch? =
        matchIn("urls", urlKeys, ThreatMatch.Kind.URL)

    override fun matchHash(hashes: FileHashes): ThreatMatch? =
        matchIn("hashes", listOf(hashes.sha256, hashes.sha1, hashes.md5), ThreatMatch.Kind.HASH)

    /** Procura qualquer um dos valores; se vários baterem, devolve o primeiro da lista (o mais específico). */
    private fun matchIn(table: String, values: List<String>, kind: ThreatMatch.Kind): ThreatMatch? {
        if (values.isEmpty()) return null
        val placeholders = values.joinToString(",") { "?" }
        val found = HashMap<String, ThreatMatch>()
        readableDatabase.rawQuery(
            "SELECT value, label, source FROM $table WHERE value IN ($placeholders)",
            values.toTypedArray(),
        ).use { c ->
            while (c.moveToNext()) {
                val v = c.getString(0)
                found[v] = ThreatMatch(kind, v, if (c.isNull(1)) null else c.getString(1), if (c.isNull(2)) null else c.getString(2))
            }
        }
        return values.firstNotNullOfOrNull { found[it] }
    }

    fun stats(): Stats {
        val db = readableDatabase
        fun count(sql: String): Int = db.rawQuery(sql, null).use { if (it.moveToFirst()) it.getInt(0) else 0 }
        return Stats(
            hashes = count("SELECT COUNT(*) FROM hashes"),
            domains = count("SELECT COUNT(*) FROM domains"),
            urls = count("SELECT COUNT(*) FROM urls"),
            importedHashes = count("SELECT COUNT(*) FROM hashes WHERE origin = $ORIGIN_IMPORTED"),
            importedDomains = count("SELECT COUNT(*) FROM domains WHERE origin = $ORIGIN_IMPORTED"),
            importedUrls = count("SELECT COUNT(*) FROM urls WHERE origin = $ORIGIN_IMPORTED"),
            bundledVersion = getMeta(META_BUNDLED_VERSION),
            bundledDate = getMeta(META_BUNDLED_DATE),
        )
    }

    // ------------------------------------------------------------- gravação

    /** Insere os itens de uma importação. Itens já existentes são mantidos. Retorna quantos eram novos. */
    fun insert(result: ImportResult, source: String, origin: Int): Int {
        val db = writableDatabase
        var added = 0
        db.beginTransaction()
        try {
            added += insertRows(db, "hashes", result.hashes.map { it.hash to it.label }, source, origin)
            added += insertRows(db, "domains", result.domains.map { it.domain to it.label }, source, origin)
            added += insertRows(db, "urls", result.urls.map { it.key to it.label }, source, origin)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        return added
    }

    private fun insertRows(db: SQLiteDatabase, table: String, rows: List<Pair<String, String?>>, source: String, origin: Int): Int {
        if (rows.isEmpty()) return 0
        var added = 0
        db.compileStatement("INSERT OR IGNORE INTO $table (value, label, source, origin) VALUES (?, ?, ?, ?)").use { st ->
            for ((value, label) in rows) {
                st.clearBindings()
                st.bindString(1, value)
                if (label == null) st.bindNull(2) else st.bindString(2, label)
                st.bindString(3, source)
                st.bindLong(4, origin.toLong())
                if (st.executeInsert() != -1L) added++
            }
        }
        return added
    }

    fun deleteByOrigin(origin: Int) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            for (t in listOf("hashes", "domains", "urls")) db.delete(t, "origin = ?", arrayOf(origin.toString()))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun getMeta(key: String): String? =
        readableDatabase.rawQuery("SELECT value FROM meta WHERE key = ?", arrayOf(key)).use {
            if (it.moveToFirst() && !it.isNull(0)) it.getString(0) else null
        }

    fun setMeta(key: String, value: String?) {
        val cv = ContentValues().apply { put("key", key); put("value", value) }
        writableDatabase.insertWithOnConflict("meta", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
    }

    companion object {
        private const val DB_NAME = "klin_kercher_ameacas.db"
        private const val DB_VERSION = 1

        const val ORIGIN_BUNDLED = 0
        const val ORIGIN_IMPORTED = 1

        const val META_BUNDLED_VERSION = "bundled_version"
        const val META_BUNDLED_DATE = "bundled_date"

        @Volatile private var instance: ThreatDatabase? = null

        fun get(context: Context): ThreatDatabase =
            instance ?: synchronized(this) {
                instance ?: ThreatDatabase(context).also { instance = it }
            }
    }
}
