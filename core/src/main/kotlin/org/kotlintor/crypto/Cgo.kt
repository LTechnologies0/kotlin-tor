package org.kotlintor.crypto

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.params.KeyParameter

/**
 * Counter Galois Onion building blocks (Prop359 / Arti CGO).
 *
 * Cell layout: TAG(16) ‖ PAYLOAD(493) = 509 bytes ([CELL_DATA_LEN]).
 * ET tweak T = TAG ‖ CMD(1) ‖ PAYLOAD (510 bytes).
 * UIV tweak H = TAG ‖ CMD (17 bytes) as used in test vectors.
 */
object Cgo {
    const val BLK_LEN = 16
    const val TAG_LEN = 16
    const val PAYLOAD_LEN = 493
    const val CELL_DATA_LEN = TAG_LEN + PAYLOAD_LEN // 509
    const val TLEN_ET = TAG_LEN + 1 + PAYLOAD_LEN // 510
    const val PRF_N0_LEN = PAYLOAD_LEN
    const val PRF_N1_OFFSET = 31 * BLK_LEN // 496
    const val KLEN_ET = 32 // KB‖KU
    const val KLEN_PRF = 32 // K‖B
    const val KLEN_UIV = KLEN_ET + KLEN_PRF // 64
    const val N1_LEN = KLEN_UIV + BLK_LEN // 80

    fun xorInto(dst: ByteArray, src: ByteArray, len: Int = dst.size) {
        for (i in 0 until len) dst[i] = (dst[i].toInt() xor src[i].toInt()).toByte()
    }

    fun xor(a: ByteArray, b: ByteArray): ByteArray =
        ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }

    fun aesEncryptBlock(key: ByteArray, block: ByteArray): ByteArray {
        require(key.size == 16 && block.size == 16)
        val eng = AESEngine.newInstance()
        eng.init(true, KeyParameter(key))
        val out = ByteArray(16)
        eng.processBlock(block, 0, out, 0)
        return out
    }

    fun aesDecryptBlock(key: ByteArray, block: ByteArray): ByteArray {
        require(key.size == 16 && block.size == 16)
        val eng = AESEngine.newInstance()
        eng.init(false, KeyParameter(key))
        val out = ByteArray(16)
        eng.processBlock(block, 0, out, 0)
        return out
    }

    /** POLYVAL with zero-padding to a 16-byte boundary (Arti `update_padded`). */
    fun polyvalPadded(h: ByteArray, message: ByteArray): ByteArray {
        val pad = (16 - (message.size % 16)) % 16
        return if (pad == 0) Polyval.polyval(h, message)
        else Polyval.polyval(h, message + ByteArray(pad))
    }

    /**
     * LRW2 tweakable block cipher.
     * `ENC_ET((KB,KU), T, M) = UH(KU,T) ⊕ AES(KB, M ⊕ UH(KU,T))`
     */
    object Et {
        fun encrypt(keys: ByteArray, tweak: ByteArray, block: ByteArray): ByteArray {
            require(keys.size == KLEN_ET && block.size == BLK_LEN)
            require(tweak.size == TLEN_ET) { "ET tweak must be $TLEN_ET bytes, got ${tweak.size}" }
            val kb = keys.copyOfRange(0, 16)
            val ku = keys.copyOfRange(16, 32)
            val tag = polyvalPadded(ku, tweak)
            val x = xor(block, tag)
            return xor(aesEncryptBlock(kb, x), tag)
        }

        fun decrypt(keys: ByteArray, tweak: ByteArray, block: ByteArray): ByteArray {
            require(keys.size == KLEN_ET && block.size == BLK_LEN)
            require(tweak.size == TLEN_ET)
            val kb = keys.copyOfRange(0, 16)
            val ku = keys.copyOfRange(16, 32)
            val tag = polyvalPadded(ku, tweak)
            val x = xor(block, tag)
            return xor(aesDecryptBlock(kb, x), tag)
        }

        /** Build flat ET tweak from UIV-style (tag16, cmd, payload493). */
        fun tweak(tag: ByteArray, cmd: Int, payload: ByteArray): ByteArray {
            require(tag.size == TAG_LEN && payload.size == PAYLOAD_LEN)
            return tag + byteArrayOf(cmd.toByte()) + payload
        }
    }

    /**
     * `PRF((K,B), T, t) = CTR(K, MASK(UH(B,T)) + t·C)` with C=31 blocks.
     * MASK clears the low six bits of the last IV byte (`&= 0xC0`).
     */
    object Prf {
        fun stream(keys: ByteArray, tweak: ByteArray, t1: Boolean, outLen: Int): ByteArray {
            require(keys.size == KLEN_PRF && tweak.size == BLK_LEN)
            val k = keys.copyOfRange(0, 16)
            val b = keys.copyOfRange(16, 32)
            val iv = polyvalPadded(b, tweak)
            iv[15] = (iv[15].toInt() and 0xC0).toByte()
            val skip = if (t1) PRF_N1_OFFSET else 0
            val total = skip + outLen
            val ks = AesCtr(k, iv).process(ByteArray(total))
            return ks.copyOfRange(skip, skip + outLen)
        }

        fun xorN0(keys: ByteArray, tweak: ByteArray, buf: ByteArray) {
            require(buf.size == PRF_N0_LEN)
            xorInto(buf, stream(keys, tweak, t1 = false, outLen = PRF_N0_LEN))
        }

        fun n1(keys: ByteArray, tweak: ByteArray, n: Int = N1_LEN): ByteArray =
            stream(keys, tweak, t1 = true, outLen = n)
    }

    /**
     * UIV+ wide-block cipher over a 509-byte cell (tag‖payload).
     * H is TAG(16)‖CMD(1) in the reference vectors.
     */
    object Uiv {
        fun encrypt(keys: ByteArray, h: ByteArray, cell: ByteArray): ByteArray {
            require(keys.size == KLEN_UIV && cell.size == CELL_DATA_LEN)
            require(h.size == TAG_LEN + 1)
            val j = keys.copyOfRange(0, KLEN_ET)
            val s = keys.copyOfRange(KLEN_ET, KLEN_UIV)
            val out = cell.copyOf()
            val left = out.copyOfRange(0, TAG_LEN)
            val right = out.copyOfRange(TAG_LEN, CELL_DATA_LEN)
            val cmd = h[TAG_LEN].toInt() and 0xff
            val tagTweak = h.copyOfRange(0, TAG_LEN)
            val yL = Et.encrypt(j, Et.tweak(tagTweak, cmd, right), left)
            Prf.xorN0(s, yL, right)
            yL.copyInto(out, 0)
            right.copyInto(out, TAG_LEN)
            return out
        }

        fun decrypt(keys: ByteArray, h: ByteArray, cell: ByteArray): ByteArray {
            require(keys.size == KLEN_UIV && cell.size == CELL_DATA_LEN)
            require(h.size == TAG_LEN + 1)
            val j = keys.copyOfRange(0, KLEN_ET)
            val s = keys.copyOfRange(KLEN_ET, KLEN_UIV)
            val out = cell.copyOf()
            val left = out.copyOfRange(0, TAG_LEN)
            val right = out.copyOfRange(TAG_LEN, CELL_DATA_LEN)
            val cmd = h[TAG_LEN].toInt() and 0xff
            val tagTweak = h.copyOfRange(0, TAG_LEN)
            Prf.xorN0(s, left, right)
            val xL = Et.decrypt(j, Et.tweak(tagTweak, cmd, right), left)
            xL.copyInto(out, 0)
            right.copyInto(out, TAG_LEN)
            return out
        }

        /** `UPDATE_UIV`: returns (newKeys[64], newNonce[16]). */
        fun update(keys: ByteArray, nonce: ByteArray): Pair<ByteArray, ByteArray> {
            require(keys.size == KLEN_UIV && nonce.size == BLK_LEN)
            val s = keys.copyOfRange(KLEN_ET, KLEN_UIV)
            val material = Prf.n1(s, nonce, N1_LEN)
            return material.copyOfRange(0, KLEN_UIV) to material.copyOfRange(KLEN_UIV, N1_LEN)
        }
    }
}
