package org.kotlintor.net

/**
 * TLS 1.2/1.3 ClientHello peek (RFC 8446 record layer + handshake).
 * Extracts SNI (RFC 6066 extension type 0) without completing the handshake —
 * for transparent / shaped Tor routing of TLS streams.
 */
object TlsClientHello {
    const val CONTENT_HANDSHAKE: Int = 0x16
    const val HANDSHAKE_CLIENT_HELLO: Int = 0x01
    const val EXT_SERVER_NAME: Int = 0x0000
    const val NAME_TYPE_HOST: Int = 0x00

    data class Peek(
        val legacyVersion: Int,
        val cipherSuites: List<Int>,
        val serverName: String?,
        /** Bytes consumed from the start of the TCP stream (full TLS record). */
        val recordLength: Int,
    )

    /**
     * Parse a TLS record starting at [offset]. Returns null if incomplete or not ClientHello.
     */
    fun parse(buf: ByteArray, offset: Int = 0): Peek? {
        if (buf.size - offset < 5) return null
        if ((buf[offset].toInt() and 0xff) != CONTENT_HANDSHAKE) return null
        val major = buf[offset + 1].toInt() and 0xff
        val minor = buf[offset + 2].toInt() and 0xff
        val recLen = ((buf[offset + 3].toInt() and 0xff) shl 8) or (buf[offset + 4].toInt() and 0xff)
        if (buf.size - offset < 5 + recLen) return null
        var o = offset + 5
        val end = o + recLen
        if (o + 4 > end) return null
        val hsType = buf[o].toInt() and 0xff
        val hsLen = ((buf[o + 1].toInt() and 0xff) shl 16) or
            ((buf[o + 2].toInt() and 0xff) shl 8) or
            (buf[o + 3].toInt() and 0xff)
        o += 4
        if (hsType != HANDSHAKE_CLIENT_HELLO) return null
        if (o + hsLen > end) return null
        val chEnd = o + hsLen
        if (o + 2 + 32 + 1 > chEnd) return null
        val legacyVersion = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
        o += 2
        o += 32 // random
        val sessionIdLen = buf[o].toInt() and 0xff
        o += 1 + sessionIdLen
        if (o + 2 > chEnd) return null
        val csLen = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
        o += 2
        if (o + csLen > chEnd) return null
        val ciphers = ArrayList<Int>(csLen / 2)
        var i = 0
        while (i + 1 < csLen) {
            ciphers += ((buf[o + i].toInt() and 0xff) shl 8) or (buf[o + i + 1].toInt() and 0xff)
            i += 2
        }
        o += csLen
        if (o + 1 > chEnd) return null
        val compLen = buf[o].toInt() and 0xff
        o += 1 + compLen
        var sni: String? = null
        if (o + 2 <= chEnd) {
            val extLen = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
            o += 2
            val extEnd = (o + extLen).coerceAtMost(chEnd)
            while (o + 4 <= extEnd) {
                val typ = ((buf[o].toInt() and 0xff) shl 8) or (buf[o + 1].toInt() and 0xff)
                val len = ((buf[o + 2].toInt() and 0xff) shl 8) or (buf[o + 3].toInt() and 0xff)
                o += 4
                if (o + len > extEnd) break
                if (typ == EXT_SERVER_NAME && len >= 5) {
                    sni = parseSni(buf, o, len)
                }
                o += len
            }
        }
        @Suppress("UNUSED_VARIABLE")
        val _mv = major to minor
        return Peek(legacyVersion, ciphers, sni, 5 + recLen)
    }

    private fun parseSni(buf: ByteArray, offset: Int, length: Int): String? {
        if (length < 2) return null
        val listLen = ((buf[offset].toInt() and 0xff) shl 8) or (buf[offset + 1].toInt() and 0xff)
        var o = offset + 2
        val end = offset + length
        if (o + listLen > end) return null
        while (o + 3 <= end) {
            val nameType = buf[o].toInt() and 0xff
            val nameLen = ((buf[o + 1].toInt() and 0xff) shl 8) or (buf[o + 2].toInt() and 0xff)
            o += 3
            if (o + nameLen > end) return null
            if (nameType == NAME_TYPE_HOST) {
                return buf.copyOfRange(o, o + nameLen).toString(Charsets.US_ASCII)
            }
            o += nameLen
        }
        return null
    }

    /** True if first byte looks like a TLS handshake record. */
    fun looksLikeTls(firstByte: Int): Boolean = (firstByte and 0xff) == CONTENT_HANDSHAKE
}
