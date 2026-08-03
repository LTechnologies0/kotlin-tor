package org.kotlintor.crypto

import org.kotlintor.util.concat

/**
 * HKDF-SHA256 (RFC 5869) used by ntor-v3 and modern Tor KDFs.
 */
object Hkdf {
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray =
        Digests.hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)

    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hashLen = 32
        val n = (length + hashLen - 1) / hashLen
        require(n <= 255)
        val out = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        for (i in 1..n) {
            t = Digests.hmacSha256(prk, concat(t, info, byteArrayOf(i.toByte())))
            val toCopy = minOf(hashLen, length - offset)
            t.copyInto(out, offset, 0, toCopy)
            offset += toCopy
        }
        return out
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray =
        expand(extract(salt, ikm), info, length)
}
