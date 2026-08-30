package org.kotlintor.circuit

import org.kotlintor.util.SecureRandomSource

/**
 * WTF-PAD histogram token machine (C Tor `circpad_state_t` histogram fields).
 *
 * Last bin is the infinity bin: choosing it means no padding scheduled
 * (`CIRCPAD_DELAY_INFINITE`).
 */
class CircpadHistogram(
    tokens: IntArray,
    /** Left edges of bins in microseconds; size == tokens.size (right edge of last is ∞). */
    private val edgesUs: LongArray,
    var removal: CircpadTokenRemoval = CircpadTokenRemoval.HIGHER,
) {
    init {
        require(tokens.size >= 2) { "histogram needs ≥2 bins" }
        require(tokens.size == edgesUs.size)
        require(tokens.size <= MAX_LEN)
        require(edgesUs.toList().zipWithNext().all { (a, b) -> a < b })
    }

    private val tokens = tokens.copyOf()
    private val initial = tokens.copyOf()
    val histogramLen: Int get() = tokens.size
    val infinityBin: Int get() = tokens.size - 1
    val totalTokens: Int get() = initial.sum()

    fun remainingTokens(): Int = tokens.sum()

    fun binsEmpty(): Boolean = remainingTokens() == 0

    /** Left edge of [bin] in microseconds (C Tor `circpad_histogram_bin_to_usec`). */
    fun binToUsec(bin: Int): Long {
        val i = bin.coerceIn(0, edgesUs.lastIndex)
        return edgesUs[i]
    }

    fun refill() {
        initial.copyInto(tokens)
    }

    /**
     * Weighted sample of a bin index; returns [infinityBin] choice as delay =
     * [Circpad.DELAY_INFINITE]. Decrements the chosen bin token.
     */
    fun sampleDelayUs(): Long {
        val total = remainingTokens()
        if (total <= 0) return Circpad.DELAY_INFINITE
        var r = SecureRandomSource.nextInt(total)
        var idx = 0
        while (idx < tokens.size) {
            if (tokens[idx] > 0) {
                if (r < tokens[idx]) break
                r -= tokens[idx]
            }
            idx++
        }
        if (idx >= tokens.size) idx = infinityBin
        if (tokens[idx] > 0) tokens[idx]--
        if (idx == infinityBin) return Circpad.DELAY_INFINITE
        val lo = edgesUs[idx]
        val hi = if (idx + 1 < edgesUs.size) edgesUs[idx + 1] else lo + 1
        return Circpad.sampleDelayUs(lo, hi - 1)
    }

    /** Bin index whose [edgesUs] range contains [delayUs] (or infinity bin). */
    fun binForDelay(delayUs: Long): Int {
        for (i in 0 until infinityBin) {
            val hi = if (i + 1 < edgesUs.size) edgesUs[i + 1] else Long.MAX_VALUE
            if (delayUs >= edgesUs[i] && delayUs < hi) return i
        }
        return infinityBin
    }

    /**
     * Remove a token for an observed non-padding delay (C Tor `circpad_machine_remove_token`).
     * Uses [removal] when the exact bin is already empty.
     */
    fun removeTokenForDelay(delayUs: Long) {
        if (removal == CircpadTokenRemoval.NONE || binsEmpty()) return
        val exact = binForDelay(delayUs)
        if (tokens[exact] > 0) {
            tokens[exact]--
            return
        }
        when (removal) {
            CircpadTokenRemoval.NONE -> Unit
            CircpadTokenRemoval.EXACT -> Unit
            CircpadTokenRemoval.HIGHER -> {
                for (i in (exact + 1) until tokens.size) {
                    if (tokens[i] > 0) {
                        tokens[i]--
                        return
                    }
                }
            }
            CircpadTokenRemoval.LOWER -> {
                for (i in (exact - 1) downTo 0) {
                    if (tokens[i] > 0) {
                        tokens[i]--
                        return
                    }
                }
            }
            CircpadTokenRemoval.CLOSEST, CircpadTokenRemoval.CLOSEST_USEC -> removeTokenClosest(delayUs)
        }
    }

    fun removeTokenClosest(delayUs: Long) {
        if (binsEmpty()) return
        var best = 0
        var bestDist = Long.MAX_VALUE
        for (i in tokens.indices) {
            if (tokens[i] <= 0) continue
            val mid = if (i == infinityBin) Long.MAX_VALUE / 4 else {
                val hi = if (i + 1 < edgesUs.size) edgesUs[i + 1] else edgesUs[i] + 1
                (edgesUs[i] + hi) / 2
            }
            val d = kotlin.math.abs(mid - delayUs)
            if (d < bestDist) {
                bestDist = d
                best = i
            }
        }
        if (tokens[best] > 0) tokens[best]--
    }

    companion object {
        const val MAX_LEN: Int = 100

        /** Example from circuitpadding.h comment (6 bins). */
        fun exampleFromSpecComment(): CircpadHistogram =
            CircpadHistogram(
                tokens = intArrayOf(6, 10, 6, 7, 9, 6),
                edgesUs = longArrayOf(0, 100, 200, 350, 500, 1000),
            )
    }
}
