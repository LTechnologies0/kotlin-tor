package org.kotlintor.hs

import org.kotlintor.crypto.Digests
import org.kotlintor.util.SecureRandomSource

/**
 * Prop327 / onion-service Proof-of-Work lite (Equi-X not implemented).
 *
 * Provides a Hashcash-style effort check against a seed for testing and
 * descriptor `pow-params` scaffolding until Equi-X is ported.
 */
object HsPow {
    data class Challenge(val seed: ByteArray, val effort: Int)

    data class Solution(val nonce: ByteArray, val seed: ByteArray, val effort: Int)

    fun challenge(effort: Int = 20): Challenge =
        Challenge(SecureRandomSource.nextBytes(32), effort)

    /** Find a nonce such that SHA256(seed‖nonce) has [effort] leading zero bits. */
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
}
