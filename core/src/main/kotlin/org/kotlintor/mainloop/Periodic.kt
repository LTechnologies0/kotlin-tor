package org.kotlintor.mainloop

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Periodic event registry (C Tor `periodic.c`).
 *
 * Inventory: `L1:core/mainloop/periodic.c`
 */
object Periodic {
    const val NO_UPDATE: Int = -1

    object Role {
        const val CLIENT: Int = 1 shl 0
        const val RELAY: Int = 1 shl 1
        const val BRIDGE: Int = 1 shl 2
        const val DIRAUTH: Int = 1 shl 3
        const val BRIDGEAUTH: Int = 1 shl 4
        const val HS_SERVICE: Int = 1 shl 5
        const val DIRSERVER: Int = 1 shl 6
        const val CONTROLEV: Int = 1 shl 7
        const val NET_PARTICIPANT: Int = 1 shl 8
        const val ALL: Int = 1 shl 9
        const val ROUTER: Int = BRIDGE or RELAY
        const val AUTHORITIES: Int = BRIDGEAUTH or DIRAUTH
    }

    object Flag {
        const val NEED_NET: Int = 1 shl 0
        const val RUN_ON_DISABLE: Int = 1 shl 1
    }

    data class EventItem(
        val name: String,
        val roles: Int,
        val flags: Int = 0,
        val intervalSec: Int,
        val action: (nowSec: Long) -> Int = { intervalSec },
    )

    private val initialized = AtomicBoolean(false)
    private val events = ConcurrentHashMap<String, EventItem>()
    private val lastRun = ConcurrentHashMap<String, Long>()

    fun init(): Int {
        initialized.set(true)
        return 0
    }

    fun shutdown() {
        events.clear()
        lastRun.clear()
        initialized.set(false)
    }

    fun isInitialized(): Boolean = initialized.get()

    fun register(item: EventItem) {
        events[item.name] = item
    }

    fun unregister(name: String) {
        events.remove(name)
        lastRun.remove(name)
    }

    fun registeredNames(): Set<String> = events.keys.toSet()

    /**
     * Run due events for [rolesMask]; returns names invoked.
     * Positive action return updates interval; [NO_UPDATE] keeps prior schedule.
     */
    fun runDue(nowSec: Long, rolesMask: Int, netDisabled: Boolean = false): List<String> {
        val ran = mutableListOf<String>()
        for (ev in events.values) {
            if (ev.roles and rolesMask == 0 && ev.roles and Role.ALL == 0) continue
            if (netDisabled && (ev.flags and Flag.NEED_NET) != 0) continue
            val last = lastRun[ev.name] ?: 0L
            if (nowSec - last < ev.intervalSec) continue
            val next = ev.action(nowSec)
            if (next != NO_UPDATE) {
                lastRun[ev.name] = nowSec
            }
            ran += ev.name
        }
        return ran
    }
}
