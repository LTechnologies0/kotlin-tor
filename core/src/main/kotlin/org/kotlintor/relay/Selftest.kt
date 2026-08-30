package org.kotlintor.relay

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Relay ORPort reachability self-test (C Tor `selftest.c`).
 *
 * Inventory: `L1:feature/relay/selftest.c`
 */
object Selftest {
    fun create(): RelaySelfTest = RelaySelfTest()
}

class RelaySelfTest {
    enum class Family { IPV4, IPV6 }

    private val reachable = ConcurrentHashMap<Family, AtomicBoolean>().also {
        it[Family.IPV4] = AtomicBoolean(false)
        it[Family.IPV6] = AtomicBoolean(false)
    }
    private val lastCheckEpochSec = AtomicLong(0)
    private val bandwidthTestBytes = AtomicLong(0)

    fun orportSeemsReachable(family: Family = Family.IPV4): Boolean =
        reachable[family]?.get() == true

    fun allOrportsSeemReachable(): Boolean =
        orportSeemsReachable(Family.IPV4) // IPv6 optional

    fun foundReachable(family: Family = Family.IPV4) {
        reachable[family]?.set(true)
    }

    fun reset() {
        reachable.values.forEach { it.set(false) }
        lastCheckEpochSec.set(0)
        bandwidthTestBytes.set(0)
    }

    /**
     * Record that we should launch reachability checks (caller dials ORPort).
     * Returns targets as (family) list.
     */
    fun doReachabilityChecks(nowEpochSec: Long = System.currentTimeMillis() / 1000): List<Family> {
        lastCheckEpochSec.set(nowEpochSec)
        return listOf(Family.IPV4)
    }

    fun performBandwidthTest(numCircs: Int, bytesPerCirc: Long = 512_000) {
        bandwidthTestBytes.addAndGet(numCircs.coerceAtLeast(0) * bytesPerCirc)
        BwHist.noteBytesWritten(bytesPerCirc * numCircs.coerceAtLeast(0))
    }

    fun bandwidthTestTotal(): Long = bandwidthTestBytes.get()
}
