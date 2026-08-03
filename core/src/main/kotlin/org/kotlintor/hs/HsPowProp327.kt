package org.kotlintor.hs

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Prop327 PoW over introduction circuits — wire format + Blake2b effort check.
 *
 * Challenge: `P || ID || C || N || htonl(E)`
 * Effort: `R = ntohl(blake2b_32(challenge || S))`; accept iff `R * E <= UINT32_MAX`.
 *
 * INTRODUCE1 extension body (EXT_FIELD_TYPE=2):
 * `POW_SCHEME(1) || NONCE(16) || EFFORT_BE(4) || SEED_HEAD(4) || SOLUTION(16)`
 */
object HsPowProp327 {
    const val PSTRING = "Tor hs intro v1\u0000"
    val PSTRING_BYTES: ByteArray = ByteArray(16).also { dst ->
        val raw = "Tor hs intro v1".toByteArray(Charsets.US_ASCII) // 15 bytes + NUL at [15]
        raw.copyInto(dst)
        dst[15] = 0
    }
    const val PSTRING_LEN = 16
    const val ID_LEN = 32
    const val SEED_LEN = 32
    const val SEED_HEAD_LEN = 4
    const val NONCE_LEN = 16
    const val EFFORT_LEN = 4
    const val EQUIX_SOL_LEN = 16
    const val POW_SCHEME_V1: Int = 1
    /** Body length inside EXT_FIELD (scheme + nonce + effort + seed_head + sol). */
    const val SOLUTION_PAYLOAD_LEN = 1 + NONCE_LEN + EFFORT_LEN + SEED_HEAD_LEN + EQUIX_SOL_LEN // 41
    const val EXT_POW_SOLUTION: Int = 2

    data class Solution(
        val seed: ByteArray,
        val nonce: ByteArray,
        val effort: Int,
        val equixSolution: ByteArray,
    ) {
        init {
            require(seed.size == SEED_LEN)
            require(nonce.size == NONCE_LEN)
            require(equixSolution.size == EQUIX_SOL_LEN)
            require(effort > 0)
        }

        fun seedHead(): ByteArray = seed.copyOf(SEED_HEAD_LEN)

        fun toBytes(): ByteArray {
            val bb = ByteBuffer.allocate(SOLUTION_PAYLOAD_LEN).order(ByteOrder.BIG_ENDIAN)
            bb.put(POW_SCHEME_V1.toByte())
            bb.put(nonce)
            bb.putInt(effort)
            bb.put(seed, 0, SEED_HEAD_LEN)
            bb.put(equixSolution)
            return bb.array()
        }

        companion object {
            fun parse(bytes: ByteArray, fullSeed: ByteArray): Solution {
                require(bytes.size == SOLUTION_PAYLOAD_LEN) { "pow solution len ${bytes.size}" }
                require(fullSeed.size == SEED_LEN)
                val bb = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
                val scheme = bb.get().toInt() and 0xff
                require(scheme == POW_SCHEME_V1) { "pow scheme $scheme" }
                val nonce = ByteArray(NONCE_LEN).also { bb.get(it) }
                val effort = bb.int
                val seedHead = ByteArray(SEED_HEAD_LEN).also { bb.get(it) }
                require(fullSeed.copyOf(SEED_HEAD_LEN).contentEquals(seedHead)) { "seed head mismatch" }
                val sol = ByteArray(EQUIX_SOL_LEN).also { bb.get(it) }
                return Solution(fullSeed.copyOf(), nonce, effort, sol)
            }
        }
    }

    /** Equi-X challenge = P ‖ ID ‖ C ‖ N ‖ htonl(E). */
    fun equixChallenge(blindedId: ByteArray, seed: ByteArray, nonce: ByteArray, effort: Int): ByteArray {
        require(blindedId.size == ID_LEN && seed.size == SEED_LEN && nonce.size == NONCE_LEN)
        val bb = ByteBuffer.allocate(PSTRING_LEN + ID_LEN + SEED_LEN + NONCE_LEN + EFFORT_LEN)
            .order(ByteOrder.BIG_ENDIAN)
        bb.put(PSTRING_BYTES)
        bb.put(blindedId)
        bb.put(seed)
        bb.put(nonce)
        bb.putInt(effort)
        return bb.array()
    }

    /** Blake2b with digest length 32 bits (not a truncated blake2b-256). */
    fun blake2b32(data: ByteArray): ByteArray {
        val d = Blake2bDigest(32)
        d.update(data, 0, data.size)
        return ByteArray(4).also { d.doFinal(it, 0) }
    }

    /** R = ntohl(blake2b_32(P‖ID‖C‖N‖E‖S)); check R * E <= UINT32_MAX. */
    fun meetsEffort(
        blindedId: ByteArray,
        seed: ByteArray,
        nonce: ByteArray,
        effort: Int,
        equixSol: ByteArray,
    ): Boolean {
        if (effort <= 0) return false
        val chal = equixChallenge(blindedId, seed, nonce, effort)
        val dig = blake2b32(concat(chal, equixSol))
        val r = ByteBuffer.wrap(dig).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xffff_ffffL
        val product = r * (effort.toLong() and 0xffff_ffffL)
        return product <= 0xffff_ffffL
    }

    fun verifySolution(sol: Solution, blindedId: ByteArray, minEffort: Int = 1): Boolean {
        if (sol.effort < minEffort) return false
        val chal = equixChallenge(blindedId, sol.seed, sol.nonce, sol.effort)
        if (!EquiX.verifyEquixBytes(chal, sol.equixSolution)) return false
        return meetsEffort(blindedId, sol.seed, sol.nonce, sol.effort, sol.equixSolution)
    }

    /**
     * Solve prop327 PoW: increment nonce, run Equi-X, check Blake2b effort.
     * Nonce is treated as a 16-byte little-endian counter (prop327).
     */
    fun solve(
        blindedId: ByteArray,
        seed: ByteArray,
        effort: Int,
        maxAttempts: Long = 50_000L,
    ): Solution? {
        require(blindedId.size == ID_LEN && seed.size == SEED_LEN && effort > 0)
        val nonce = SecureRandomSource.nextBytes(NONCE_LEN)
        var attempts = 0L
        while (attempts < maxAttempts) {
            val chal = equixChallenge(blindedId, seed, nonce, effort)
            val sols = org.kotlintor.pow.EquiX.solve(chal)
            for (eq in sols) {
                val equixSol = eq.toBytes()
                if (meetsEffort(blindedId, seed, nonce, effort, equixSol)) {
                    return Solution(seed.copyOf(), nonce.copyOf(), effort, equixSol)
                }
            }
            incrementNonceLe(nonce)
            attempts++
        }
        return null
    }

    fun incrementNonceLe(nonce: ByteArray) {
        for (i in nonce.indices) {
            val v = (nonce[i].toInt() and 0xff) + 1
            nonce[i] = v.toByte()
            if (v < 256) return
        }
    }

    fun encodeExtension(sol: Solution): ByteArray {
        val body = sol.toBytes()
        return byteArrayOf(EXT_POW_SOLUTION.toByte(), body.size.toByte()) + body
    }

    fun parseExtension(payload: ByteArray, offset: Int = 0, fullSeed: ByteArray): Pair<Solution?, Int> {
        if (offset + 2 > payload.size) return null to offset
        val type = payload[offset].toInt() and 0xff
        val len = payload[offset + 1].toInt() and 0xff
        val next = offset + 2 + len
        if (type != EXT_POW_SOLUTION || len != SOLUTION_PAYLOAD_LEN || next > payload.size) {
            return null to next.coerceAtMost(payload.size)
        }
        return Solution.parse(payload.copyOfRange(offset + 2, next), fullSeed) to next
    }
}
