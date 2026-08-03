package org.kotlintor.pow

/** SipHash-based PRNG used by HashX program generation (siphash_rng.c). */
class SipHashRng {
    val keys = SipHashState()
    var counter: Long = 0
    private var buffer8: Long = 0
    private var buffer32: Long = 0
    private var count8: Int = 0
    private var count32: Int = 0

    fun init(state: SipHashState) {
        keys.copyFrom(state)
        counter = 0
        count8 = 0
        count32 = 0
        buffer8 = 0
        buffer32 = 0
    }

    fun u8(): Int {
        if (count8 == 0) {
            buffer8 = SipHash.siphash13Ctr(counter, keys)
            counter++
            count8 = 8
        }
        count8--
        return ((buffer8 ushr (count8 * 8)) and 0xffL).toInt()
    }

    fun u32(): Int {
        if (count32 == 0) {
            buffer32 = SipHash.siphash13Ctr(counter, keys)
            counter++
            count32 = 2
        }
        count32--
        return ((buffer32 ushr (count32 * 32)) and 0xffff_ffffL).toInt()
    }
}
