package org.kotlintor.crypto

import org.bouncycastle.crypto.modes.gcm.GCMUtil

/**
 * POLYVAL (RFC 8452) for CGO (Prop359).
 *
 * Implemented via the RFC conversion:
 * `POLYVAL(H, X…) = ByteReverse(GHASH(ByteReverse(H)·x, ByteReverse(X)…))`
 */
object Polyval {
    fun polyval(h: ByteArray, message: ByteArray): ByteArray = polyval(h, listOf(message))

    fun polyval(h: ByteArray, messages: List<ByteArray>): ByteArray {
        require(h.size == 16)
        // H' = ByteReverse(H) * x  in the GHASH field
        val hRev = h.reversedArray()
        val hLongs = GCMUtil.asLongs(hRev)
        GCMUtil.multiplyP(hLongs)
        val hp = GCMUtil.asBytes(hLongs)

        var y = ByteArray(16)
        for (msg in messages) {
            require(msg.size % 16 == 0) { "POLYVAL messages must be 16-byte blocks" }
            var off = 0
            while (off < msg.size) {
                val xRev = msg.copyOfRange(off, off + 16).reversedArray()
                for (i in 0 until 16) {
                    y[i] = (y[i].toInt() xor xRev[i].toInt()).toByte()
                }
                GCMUtil.multiply(y, hp)
                off += 16
            }
        }
        return y.reversedArray()
    }
}
