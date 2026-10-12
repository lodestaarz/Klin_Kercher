package com.example.klin_kercher.data

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns

/** Nome e tamanho de um arquivo recebido pelo seletor de arquivos ou por compartilhamento. */
data class UriFileInfo(val name: String, val size: Long?)

object UriFiles {

    fun info(resolver: ContentResolver, uri: Uri): UriFileInfo {
        var name: String? = null
        var size: Long? = null
        try {
            resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val si = c.getColumnIndex(OpenableColumns.SIZE)
                    if (ni >= 0 && !c.isNull(ni)) name = c.getString(ni)
                    if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
                }
            }
        } catch (e: Exception) {
            // alguns aplicativos não respondem a consultas; usamos o fim do endereço como nome
        }
        val fallback = uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotBlank() } ?: "arquivo"
        return UriFileInfo(name ?: fallback, size?.takeIf { it >= 0 })
    }
}
