package org.kotlintor.hs

import org.kotlintor.crypto.Digests
import org.kotlintor.util.SecureRandomSource

/**
 * Descriptor `pow-params` scaffolding and C Tor `hs_pow_*` naming.
 *
 * Elevated [hsPowSolve] / [hsPowVerify] are prop327 Equi-X + Blake2b via [HsPowProp327].
 * The SHA256 leading-zero solve/verify helpers are **not** C Tor Equi-X
 * (kept only for descriptor-line / queue scaffolding).
 *
 * Inventory: `L1:feature/hs/hs_pow.c`
 */
object HsPow {
    data class Challenge(val seed: ByteArray, val effort: Int)

    data class Solution(val nonce: ByteArray, val seed: ByteArray, val effort: Int)

    fun challenge(effort: Int = 20): Challenge =
        Challenge(SecureRandomSource.nextBytes(32), effort)

    /** SHA256 leading-zero solver — **not** C Tor Equi-X; see [hsPowSolve]. */
    fun solve(challenge: Challenge, maxAttempts: Long = 1_000_000L): Solution? {
        val nonce = ByteArray(16)
        var attempts = 0L
        while (attempts < maxAttempts) {
            val fresh = SecureRandomSource.nextBytes(16)
            fresh.copyInto(nonce)
            if (meetsEffort(challenge.seed, nonce, challenge.effort)) {
                return Solution(nonce.copyOf(), challenge.seed.copyOf(), challenge.effort)
            }
            attempts++
        }
        return null
    }

    fun verify(solution: Solution): Boolean =
        meetsEffort(solution.seed, solution.nonce, solution.effort)

    fun meetsEffort(seed: ByteArray, nonce: ByteArray, effort: Int): Boolean {
        if (effort <= 0) return true
        val dig = Digests.sha256(seed + nonce)
        var bits = effort
        var i = 0
        while (bits >= 8) {
            if (dig[i].toInt() != 0) return false
            i++; bits -= 8
        }
        if (bits == 0) return true
        val mask = (0xff shl (8 - bits)) and 0xff
        return (dig[i].toInt() and 0xff and mask) == 0
    }

    /** Descriptor line: `pow-params v1 <seed-b64> <effort> <expiration>` */
    fun powParamsLine(challenge: Challenge, expirationEpoch: Long): String {
        val b64 = java.util.Base64.getEncoder().withoutPadding()
            .encodeToString(challenge.seed)
        return "pow-params v1 $b64 ${challenge.effort} $expirationEpoch"
    }

    private val seedCache = java.util.concurrent.ConcurrentHashMap<String, Challenge>()
    private val workQueue = java.util.concurrent.ConcurrentLinkedQueue<Challenge>()
    @Volatile private var serviceStateAlive: Boolean = true

    /** C Tor `hs_pow_solve` — prop327 Equi-X + Blake2b ([HsPowProp327.solve]). */
    fun hsPowSolve(
        blindedId: ByteArray,
        seed: ByteArray,
        effort: Int,
        maxAttempts: Long = 50_000L,
    ): HsPowProp327.Solution? =
        HsPowProp327.solve(blindedId, seed, effort, maxAttempts)

    /** C Tor `hs_pow_verify` — prop327 ([HsPowProp327.verifySolution]). */
    fun hsPowVerify(
        solution: HsPowProp327.Solution,
        blindedId: ByteArray,
        minEffort: Int = 1,
    ): Boolean = HsPowProp327.verifySolution(solution, blindedId, minEffort)

    /** C Tor `hs_pow_queue_work`. */
    fun hsPowQueueWork(challenge: Challenge): Int {
        workQueue.offer(challenge)
        seedCache[challenge.seed.contentHashCode().toString()] = challenge
        return workQueue.size
    }

    /** C Tor `hs_pow_remove_seed_from_cache`. */
    fun hsPowRemoveSeedFromCache(seed: ByteArray): Boolean =
        seedCache.remove(seed.contentHashCode().toString()) != null

    /** C Tor `hs_pow_free_service_state`. */
    fun hsPowFreeServiceState() {
        workQueue.clear()
        seedCache.clear()
        serviceStateAlive = false
    }

    fun hsPowServiceStateAlive(): Boolean = serviceStateAlive
}
