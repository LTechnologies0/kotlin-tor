package org.kotlintor.relay

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Lightweight DoS defenses (tor DoS subsystem subset):
 * per-IP connection cap, circuit-create rate, concurrent create burst,
 * optional stream-create rate.
 */
class DosGuard(
    private val maxConnsPerIp: Int = 32,
    private val maxCreatesPerMin: Int = 100,
    private val maxConcurrentCreates: Int = 8,
    private val maxStreamsPerMin: Int = Int.MAX_VALUE / 4,
    private val streamDefenseEnabled: Boolean = false,
) {
    private data class IpState(
        val conns: AtomicInteger = AtomicInteger(0),
        val creates: AtomicInteger = AtomicInteger(0),
        val concurrentCreates: AtomicInteger = AtomicInteger(0),
        val streams: AtomicInteger = AtomicInteger(0),
        @Volatile var windowStartMs: Long = System.currentTimeMillis(),
        @Volatile var streamWindowStartMs: Long = System.currentTimeMillis(),
    )

    private val byIp = ConcurrentHashMap<String, IpState>()

    fun allowConnection(ip: String): Boolean {
        val st = byIp.getOrPut(ip) { IpState() }
        return st.conns.incrementAndGet() <= maxConnsPerIp
    }

    fun releaseConnection(ip: String) {
        byIp[ip]?.conns?.updateAndGet { (it - 1).coerceAtLeast(0) }
    }

    fun allowCreate(ip: String): Boolean {
        val st = byIp.getOrPut(ip) { IpState() }
        val now = System.currentTimeMillis()
        if (now - st.windowStartMs > 60_000) {
            st.windowStartMs = now
            st.creates.set(0)
        }
        if (st.concurrentCreates.get() >= maxConcurrentCreates) return false
        if (st.creates.incrementAndGet() > maxCreatesPerMin) return false
        st.concurrentCreates.incrementAndGet()
        return true
    }

    fun releaseCreate(ip: String) {
        byIp[ip]?.concurrentCreates?.updateAndGet { (it - 1).coerceAtLeast(0) }
    }

    fun allowStream(ip: String): Boolean {
        if (!streamDefenseEnabled) return true
        val st = byIp.getOrPut(ip) { IpState() }
        val now = System.currentTimeMillis()
        if (now - st.streamWindowStartMs > 60_000) {
            st.streamWindowStartMs = now
            st.streams.set(0)
        }
        return st.streams.incrementAndGet() <= maxStreamsPerMin
    }

    companion object {
        fun fromOptions(o: DosOptions): DosGuard = o.toGuard()
    }
}
