package org.kotlintor.crypto

import org.bouncycastle.crypto.digests.SHAKEDigest

/** SHAKE256 XOF helpers (rend-spec HS descriptor KDF). */
object Shake256 {
    fun xof(input: ByteArray, outLen: Int): ByteArray {
        val d = SHAKEDigest(256)
        d.update(input, 0, input.size)
        return ByteArray(outLen).also { d.doFinal(it, 0, outLen) }
    }
}
