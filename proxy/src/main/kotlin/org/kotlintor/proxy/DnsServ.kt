package org.kotlintor.proxy

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * DNSPort / dnsserv helpers (C Tor `dnsserv.c` / `dnsserv.h`).
 *
 * Inventory: `L1:feature/client/dnsserv.c`
 */
object DnsServ {
    data class Query(val name: String, val type: Int = 1 /* A */)

    data class Listener(val host: String, val port: Int)

    private val listening = AtomicBoolean(false)
    private var listener: Listener? = null
    private val pending = CopyOnWriteArrayList<Query>()
    private val resolved = CopyOnWriteArrayList<Pair<Query, String>>()
    private val rejected = CopyOnWriteArrayList<Query>()

    fun normalizeName(name: String): String = name.trim().trimEnd('.').lowercase()

    fun isOnion(name: String): Boolean = normalizeName(name).endsWith(".onion")

    fun shouldAutomap(name: String): Boolean {
        val n = normalizeName(name)
        return n.endsWith(".onion") || n.endsWith(".exit")
    }

    /** C Tor `dnsserv_configure_listener`. */
    fun dnsservConfigureListener(host: String, port: Int): Listener {
        val l = Listener(host, port)
        listener = l
        listening.set(true)
        return l
    }

    /** C Tor `dnsserv_close_listener`. */
    fun dnsservCloseListener() {
        listening.set(false)
        listener = null
        pending.clear()
    }

    /** C Tor `dnsserv_launch_request`. */
    fun dnsservLaunchRequest(name: String, type: Int = 1): Query {
        val q = Query(normalizeName(name), type)
        if (!listening.get()) {
            dnsservRejectRequest(q)
            return q
        }
        if (q.name.isEmpty()) {
            dnsservRejectRequest(q)
            return q
        }
        pending += q
        return q
    }

    /** C Tor `dnsserv_reject_request`. */
    fun dnsservRejectRequest(query: Query) {
        pending.remove(query)
        rejected += query
    }

    /** C Tor `dnsserv_resolved`. */
    fun dnsservResolved(query: Query, address: String) {
        pending.remove(query)
        resolved += query to address
    }

    fun isListening(): Boolean = listening.get()
    fun currentListener(): Listener? = listener
    fun pendingRequests(): List<Query> = pending.toList()
    fun resolvedAnswers(): List<Pair<Query, String>> = resolved.toList()
    fun rejectedRequests(): List<Query> = rejected.toList()

    fun resetForTests() {
        dnsservCloseListener()
        resolved.clear()
        rejected.clear()
    }
}
