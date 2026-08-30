package org.kotlintor.circuit

/**
 * Tor1 relay crypto state mirror (C Tor `tor1_crypt_t`).
 *
 * Inventory: `L2:core/crypto/tor1_crypt_t`
 *
 * Runtime crypto: [HopCrypto] / [RelayCryptoTor1].
 */
data class Tor1Crypt(
    val forwardKey: ByteArray = ByteArray(16),
    val backwardKey: ByteArray = ByteArray(16),
    val forwardDigestSeed: ByteArray = ByteArray(20),
    val backwardDigestSeed: ByteArray = ByteArray(20),
) {
    init {
        require(forwardKey.size == 16 && backwardKey.size == 16) { "AES-128 keys" }
        require(forwardDigestSeed.size == 20 && backwardDigestSeed.size == 20) { "SHA1 digests" }
    }

    fun toHopCrypto(): HopCrypto =
        HopCrypto.legacy(forwardDigestSeed, backwardDigestSeed, forwardKey, backwardKey)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Tor1Crypt) return false
        return forwardKey.contentEquals(other.forwardKey) &&
            backwardKey.contentEquals(other.backwardKey) &&
            forwardDigestSeed.contentEquals(other.forwardDigestSeed) &&
            backwardDigestSeed.contentEquals(other.backwardDigestSeed)
    }

    override fun hashCode(): Int {
        var r = forwardKey.contentHashCode()
        r = 31 * r + backwardKey.contentHashCode()
        r = 31 * r + forwardDigestSeed.contentHashCode()
        r = 31 * r + backwardDigestSeed.contentHashCode()
        return r
    }
}
