package org.kotlintor.dir

/**
 * Directory document signing helpers (C Tor `signing.c`).
 *
 * Inventory: `L1:feature/dirparse/signing.c`
 */
object DirSigning {
    fun sha1DigestHex(document: String): String =
        org.kotlintor.crypto.Digests.sha1(document.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02X".format(it.toInt() and 0xff) }

    fun findSignatureBlock(document: String, begin: String = "-----BEGIN SIGNATURE-----"): String? {
        val start = document.indexOf(begin)
        if (start < 0) return null
        val endMark = begin.replace("BEGIN", "END")
        val end = document.indexOf(endMark, start)
        if (end < 0) return null
        return document.substring(start, end + endMark.length)
    }

    fun stripSignatures(document: String): String {
        val idx = document.indexOf("-----BEGIN SIGNATURE-----")
        return if (idx < 0) document else document.substring(0, idx)
    }
}

object Signing {
    fun sha1DigestHex(document: String) = DirSigning.sha1DigestHex(document)
    fun stripSignatures(document: String) = DirSigning.stripSignatures(document)
}
