package org.kotlintor.control

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * ORCONN bootstrap-tracking record (C Tor `bt_orconn_t`).
 */
data class BtOrconn(
    var gid: Long = 0,
    var chan: Long = 0,
    var proxyType: Int = 0,
    var state: Int = 0,
    var isOrig: Boolean = false,
    var isOnehop: Boolean = true,
    /** Optional controller-facing target string (kotlin-tor extension). */
    var target: String = "",
) {
    companion object {
        const val PROXY_NONE = 0
        const val PROXY_CONNECT = 1
        const val PROXY_SOCKS4 = 2
        const val PROXY_SOCKS5 = 3
        const val PROXY_HAPROXY = 4
        const val PROXY_PLUGGABLE = 5

        const val STATE_CONNECTING = 1
        const val STATE_PROXY_HANDSHAKING = 2
        const val STATE_TLS_HANDSHAKING = 3
        const val STATE_SERVER_VERSIONS_WAIT = 4
        const val STATE_OR_HANDSHAKING_V3 = 5
        const val STATE_OPEN = 6
    }
}

/**
 * ORCONN id→target maps for bootstrap tracking (C Tor `btrack_orconn_maps.c`).
 *
 * Inventory: `L1:feature/control/btrack_orconn_maps.c`
 */
object BtrackOrconnMaps {
    private val byGid = ConcurrentHashMap<Long, BtOrconn>()
    private val byChan = ConcurrentHashMap<Long, BtOrconn>()
    private val initialized = AtomicBoolean(false)

    /** Legacy target-only map helpers used by older call sites. */
    fun put(connId: Long, target: String) {
        val bto = btoFindOrNew(connId, 0)
        bto.target = target
    }

    fun get(connId: Long): String? = byGid[connId]?.target?.takeIf { it.isNotEmpty() }

    fun remove(connId: Long): String? {
        val prev = get(connId)
        btoDelete(connId)
        return prev
    }

    fun clear() = btoClearMaps()

    fun size(): Int = byGid.size

    /** C Tor `bto_init_maps`. */
    fun btoInitMaps() {
        byGid.clear()
        byChan.clear()
        initialized.set(true)
    }

    /** C Tor `bto_clear_maps`. */
    fun btoClearMaps() {
        byGid.clear()
        byChan.clear()
        initialized.set(false)
    }

    fun mapsInitialized(): Boolean = initialized.get()

    /** C Tor `bto_delete`. */
    fun btoDelete(gid: Long) {
        val bto = byGid.remove(gid) ?: return
        if (bto.chan != 0L) byChan.remove(bto.chan)
    }

    /**
     * C Tor `bto_find_or_new` — insert or update by GID and/or channel id.
     * At least one of [gid]/[chan] must be non-zero.
     */
    fun btoFindOrNew(gid: Long, chan: Long): BtOrconn {
        require(gid != 0L || chan != 0L) { "gid or chan required" }
        if (!initialized.get()) btoInitMaps()
        var bto: BtOrconn? = null
        if (gid != 0L) bto = byGid[gid]
        if (bto == null && chan != 0L) bto = byChan[chan]
        if (bto != null) {
            if (bto.gid == 0L && gid != 0L) {
                bto.gid = gid
                byGid[gid] = bto
            }
            if (bto.chan == 0L && chan != 0L) {
                bto.chan = chan
                byChan[chan] = bto
            }
            return bto
        }
        val created = BtOrconn(gid = gid, chan = chan)
        if (gid != 0L) byGid[gid] = created
        if (chan != 0L) byChan[chan] = created
        return created
    }
}
