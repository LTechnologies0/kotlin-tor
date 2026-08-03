package org.kotlintor.pow

import org.bouncycastle.crypto.digests.Blake2bDigest
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * HashX interpreted mode with HASHX_SIZE=8 (Equi-X configuration).
 *
 * Blake2b parameter block matches `hashx_blake2_params` in hashx `context.c`
 * (salt = `"HashX v1"` C string padded to 16 bytes).
 */
class HashX {
    val program = HashXProgram()
    val keys = SipHashState() // second 32 bytes of blake2 output (keys[1])
    var ready: Boolean = false
        private set

    fun make(seed: ByteArray): Boolean {
        val keyMaterial = blake2Params(seed)
        // keys[0] = first 32 bytes, keys[1] = second 32 bytes as two siphash_state
        val key0 = SipHashState(
            load64(keyMaterial, 0),
            load64(keyMaterial, 8),
            load64(keyMaterial, 16),
            load64(keyMaterial, 24),
        )
        keys.v0 = load64(keyMaterial, 32)
        keys.v1 = load64(keyMaterial, 40)
        keys.v2 = load64(keyMaterial, 48)
        keys.v3 = load64(keyMaterial, 56)
        ready = HashXProgramGenerate.generate(key0, program)
        return ready
    }

    /** Execute HashX; writes HASHX_SIZE (8) little-endian bytes to [out]. */
    fun exec(input: Long, out: ByteArray, outOff: Int = 0) {
        check(ready) { "hashx program not ready" }
        require(out.size - outOff >= HASHX_SIZE)
        val r = LongArray(8)
        SipHash.siphash24CtrState512(keys, input, r)
        HashXProgramExec.execute(program, r)
        r[0] += keys.v0
        r[1] += keys.v1
        r[6] += keys.v2
        r[7] += keys.v3
        val t0 = SipHashState(r[0], r[1], r[2], r[3])
        SipHash.sipRound(t0)
        val t1 = SipHashState(r[4], r[5], r[6], r[7])
        SipHash.sipRound(t1)
        store64(out, outOff, t0.v0 xor t1.v0)
    }

    fun execValue(input: Long): Long {
        val buf = ByteArray(HASHX_SIZE)
        exec(input, buf)
        return load64(buf, 0)
    }

    companion object {
        const val HASHX_SIZE = 8

        /** `hashx_blake2_params` salt = STRINGIZE(HashX v1) → `"HashX v1\0..."` */
        private val BLAKE2_SALT: ByteArray = ByteArray(16).also { s ->
            val ascii = "HashX v1".toByteArray(Charsets.US_ASCII)
            ascii.copyInto(s)
            // C string literal includes NUL at index 8; remaining already 0
        }

        private val BLAKE2_PERSONAL = ByteArray(16)

        fun blake2Params(seed: ByteArray): ByteArray {
            // digest_length=64, key=null, salt, personal — matches hashx_blake2_params
            val d = Blake2bDigest(null, 64, BLAKE2_SALT, BLAKE2_PERSONAL)
            d.update(seed, 0, seed.size)
            return ByteArray(64).also { d.doFinal(it, 0) }
        }

        fun load64(b: ByteArray, off: Int): Long =
            ByteBuffer.wrap(b, off, 8).order(ByteOrder.LITTLE_ENDIAN).long

        fun store64(b: ByteArray, off: Int, v: Long) {
            ByteBuffer.wrap(b, off, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(v)
        }
    }
}
