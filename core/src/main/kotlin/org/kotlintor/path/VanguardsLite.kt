package org.kotlintor.path

import org.kotlintor.config.TorConfig
import org.kotlintor.dir.RouterStatus
import org.kotlintor.util.SecureRandomSource

/**
 * Vanguards-lite (prop344 / torrc VanguardsLiteEnabled): pin L2/L3 relays for
 * onion-service circuits so middle hops are less predictable.
 *
 * Full vanguards-full (L2 set of 4, L3 set of 8 with rotation) is approximated
 * here with a sticky sample of [L2_SIZE] / [L3_SIZE] high-bandwidth relays.
 */
class VanguardsLite(
    private val config: TorConfig,
) {
    private val l2 = mutableListOf<String>() // fingerprint hex
    private val l3 = mutableListOf<String>()

    fun ensureSampled(relays: List<RouterStatus>) {
        if (!config.vanguardsLiteEnabled) return
        val pool = relays.filter { it.isRunning && it.isFast && it.isStable }
            .sortedByDescending { it.bandwidth }
        if (l2.size < L2_SIZE) {
            for (r in pool) {
                if (r.fingerprintHex in l2 || r.fingerprintHex in l3) continue
                l2 += r.fingerprintHex
                if (l2.size >= L2_SIZE) break
            }
        }
        if (l3.size < L3_SIZE) {
            for (r in pool) {
                if (r.fingerprintHex in l2 || r.fingerprintHex in l3) continue
                l3 += r.fingerprintHex
                if (l3.size >= L3_SIZE) break
            }
        }
    }

    /** HS path: Guard → L2 → L3 → destination (intro/rend/HSDir). */
    fun selectHsPath(
        relays: List<RouterStatus>,
        lastHop: RouterStatus,
        pickGuard: (List<RouterStatus>) -> RouterStatus,
    ): CircuitPath {
        ensureSampled(relays)
        val byFp = relays.associateBy { it.fingerprintHex }
        val exclude = (config.excludeNodes.map { it.uppercase() } + lastHop.fingerprintHex).toSet()
        val guards = relays.filter { it.isGuard && it.isRunning && it.fingerprintHex !in exclude }
        require(guards.isNotEmpty()) { "no guards for vanguards path" }
        val guard = pickGuard(guards)
        val l2Relay = pickFrom(l2, byFp, setOf(guard.fingerprintHex, lastHop.fingerprintHex))
            ?: relays.first { it.fingerprintHex != guard.fingerprintHex && it.fingerprintHex != lastHop.fingerprintHex }
        val l3Relay = pickFrom(l3, byFp, setOf(guard.fingerprintHex, l2Relay.fingerprintHex, lastHop.fingerprintHex))
            ?: lastHop
        // 4-hop conceptual path truncated to CircuitPath(guard, middle=L2, exit=last)
        // when destination is lastHop; L3 used when lastHop is not L3.
        val middle = if (l3Relay.fingerprintHex == lastHop.fingerprintHex) l2Relay else l2Relay
        return CircuitPath(guard, middle, lastHop)
    }

    fun l2Fingerprints(): List<String> = l2.toList()
    fun l3Fingerprints(): List<String> = l3.toList()

    private fun pickFrom(
        fps: List<String>,
        byFp: Map<String, RouterStatus>,
        exclude: Set<String>,
    ): RouterStatus? {
        val candidates = fps.mapNotNull { byFp[it] }.filter { it.fingerprintHex !in exclude }
        if (candidates.isEmpty()) return null
        return candidates[SecureRandomSource.nextInt(candidates.size)]
    }

    companion object {
        const val L2_SIZE = 4
        const val L3_SIZE = 8
    }
}
