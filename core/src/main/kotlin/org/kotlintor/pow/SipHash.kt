package org.kotlintor.pow

/** Mutable SipHash state (v0..v3). */
class SipHashState(
    var v0: Long = 0,
    var v1: Long = 0,
    var v2: Long = 0,
    var v3: Long = 0,
) {
    fun copyFrom(other: SipHashState) {
        v0 = other.v0; v1 = other.v1; v2 = other.v2; v3 = other.v3
    }

    fun loadFrom(bytes: ByteArray, offset: Int = 0) {
        require(bytes.size >= offset + 32)
        fun le(o: Int): Long {
            var x = 0L
            for (i in 0..7) x = x or ((bytes[offset + o + i].toLong() and 0xff) shl (8 * i))
            return x
        }
        v0 = le(0); v1 = le(8); v2 = le(16); v3 = le(24)
    }
}

/**
 * SipHash helpers for HashX (tevador) — counter mode primitives.
 */
object SipHash {
    fun rotl(x: Long, b: Int): Long = (x shl b) or (x ushr (64 - b))

    fun sipRound(s: SipHashState) {
        s.v0 += s.v1
        s.v2 += s.v3
        s.v1 = rotl(s.v1, 13)
        s.v3 = rotl(s.v3, 16)
        s.v1 = s.v1 xor s.v0
        s.v3 = s.v3 xor s.v2
        s.v0 = rotl(s.v0, 32)
        s.v2 += s.v1
        s.v0 += s.v3
        s.v1 = rotl(s.v1, 17)
        s.v3 = rotl(s.v3, 21)
        s.v1 = s.v1 xor s.v2
        s.v3 = s.v3 xor s.v0
        s.v2 = rotl(s.v2, 32)
    }

    fun siphash13Ctr(input: Long, keys: SipHashState): Long {
        val s = SipHashState(keys.v0, keys.v1, keys.v2, keys.v3 xor input)
        sipRound(s)
        s.v0 = s.v0 xor input
        s.v2 = s.v2 xor 0xffL
        sipRound(s); sipRound(s); sipRound(s)
        return (s.v0 xor s.v1) xor (s.v2 xor s.v3)
    }

    fun siphash24CtrState512(keys: SipHashState, input: Long, out: LongArray) {
        require(out.size >= 8)
        val s = SipHashState(keys.v0, keys.v1 xor 0xeeL, keys.v2, keys.v3 xor input)
        sipRound(s); sipRound(s)
        s.v0 = s.v0 xor input
        s.v2 = s.v2 xor 0xeeL
        sipRound(s); sipRound(s); sipRound(s); sipRound(s)
        out[0] = s.v0; out[1] = s.v1; out[2] = s.v2; out[3] = s.v3
        s.v1 = s.v1 xor 0xddL
        sipRound(s); sipRound(s); sipRound(s); sipRound(s)
        out[4] = s.v0; out[5] = s.v1; out[6] = s.v2; out[7] = s.v3
    }
}
