package org.kotlintor.dir

import org.kotlintor.util.toHex

/**
 * Fingerprint pair (RSA + Ed25519) helper (C Tor `fp_pair.c`).
 */
data class FpPair(val rsaIdHex: String, val ed25519Hex: String) {
    init {
        require(rsaIdHex.length == 40)
        require(ed25519Hex.length == 64)
    }

    companion object {
        fun of(rsa: ByteArray, ed: ByteArray): FpPair {
            require(rsa.size == 20 && ed.size == 32)
            return FpPair(rsa.toHex().lowercase(), ed.toHex().lowercase())
        }
    }
}
