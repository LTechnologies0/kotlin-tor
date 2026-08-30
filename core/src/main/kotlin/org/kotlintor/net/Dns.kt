package org.kotlintor.net

/**
 * Exit DNS helpers (C Tor `dns.c`).
 *
 * Inventory: `L1:feature/relay/dns.c`
 */
object Dns {
    fun isOnion(host: String): Boolean = host.endsWith(".onion", ignoreCase = true)
    fun normalize(host: String): String = host.trim().lowercase()
}
