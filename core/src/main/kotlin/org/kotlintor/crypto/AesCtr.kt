package org.kotlintor.crypto

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * AES-CTR as used by Tor relay crypto (AES-128, zero IV, counter in big-endian).
 */
class AesCtr(key: ByteArray, iv: ByteArray = ByteArray(16)) {
    private val cipher = SICBlockCipher.newInstance(AESEngine.newInstance())

    init {
        require(key.size == 16 || key.size == 32) { "AES key must be 128 or 256 bits" }
        require(iv.size == 16) { "IV must be 16 bytes" }
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))
    }

    fun process(input: ByteArray, offset: Int = 0, length: Int = input.size - offset): ByteArray {
        val out = ByteArray(length)
        cipher.processBytes(input, offset, length, out, 0)
        return out
    }

    fun processInPlace(buf: ByteArray, offset: Int = 0, length: Int = buf.size - offset) {
        cipher.processBytes(buf, offset, length, buf, offset)
    }
}
