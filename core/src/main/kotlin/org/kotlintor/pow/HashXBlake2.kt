package org.kotlintor.pow

import org.bouncycastle.crypto.digests.Blake2bDigest

/**
 * HashX Blake2b seed → two SipHash key states (64 bytes).
 * Params match tevador hashx: digest_length=64, salt="HashX v1".
 */
internal object HashXBlake2 {
    private val SALT = "HashX v1".toByteArray(Charsets.US_ASCII).copyOf(16)
    private val PERSONAL = ByteArray(16)

    fun deriveKeys(seed: ByteArray): Pair<SipHashState, SipHashState> {
        val d = Blake2bDigest(/*key*/ null, /*digestLength*/ 64, SALT, PERSONAL)
        d.update(seed, 0, seed.size)
        val out = ByteArray(64)
        d.doFinal(out, 0)
        val k0 = SipHashState().also { it.loadFrom(out, 0) }
        val k1 = SipHashState().also { it.loadFrom(out, 32) }
        return k0 to k1
    }
}
