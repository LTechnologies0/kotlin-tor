package org.kotlintor.path

import org.kotlintor.config.TorConfig
import org.kotlintor.dir.RouterStatus
import org.kotlintor.util.SecureRandomSource
import java.util.concurrent.TimeUnit

/**
 * Vanguards-lite (prop344 / torrc VanguardsLiteEnabled): pin L2/L3 relays for
 * onion-service circuits so middle hops are less predictable.
 *
 * Sample is **random** over the eligible pool (not top-bandwidth-only) and
 * rotated on [ROTATE_MS].
 */
class VanguardsLite(
    private val config: TorConfig,
) {
    private val l2 = mutableListOf<String>()
    private val l3 = mutableListOf<String>()
    private var lastRotateMs: Long = 0L

    fun ensureSampled(relays: List<RouterStatus>) {
        if (!config.vanguardsLiteEnabled) return
        val now = System.currentTimeMillis()
        if (lastRotateMs != 0L && now - lastRotateMs >= ROTATE_MS) {
            l2.clear()
            l3.clear()
        }
        val pool = relays.filter { it.isRunning && it.isFast && it.isStable }
        if (pool.isEmpty()) return
        if (l2.size < L2_SIZE || l3.size < L3_SIZE) {
            lastRotateMs = now
        }
        fillRandom(l2, L2_SIZE, pool, exclude = l3)
        fillRandom(l3, L3_SIZE, pool, exclude = l2)
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
        val middle = if (l3Relay.fingerprintHex == lastHop.fingerprintHex) l2Relay else l2Relay
        return CircuitPath(guard, middle, lastHop)
    }

    fun l2Fingerprints(): List<String> = l2.toList()
    fun l3Fingerprints(): List<String> = l3.toList()

    private fun fillRandom(
        dest: MutableList<String>,
        size: Int,
        pool: List<RouterStatus>,
        exclude: List<String>,
    ) {
        val taken = (dest + exclude).toMutableSet()
        val cand = pool.filter { it.fingerprintHex !in taken }.toMutableList()
        while (dest.size < size && cand.isNotEmpty()) {
            val i = SecureRandomSource.nextInt(cand.size)
            val pick = cand.removeAt(i)
            dest += pick.fingerprintHex
            taken += pick.fingerprintHex
        }
    }

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
        /** Rotate L2/L3 on this order of magnitude (vanguards-lite). */
        val ROTATE_MS: Long = TimeUnit.DAYS.toMillis(7)
    }
}
