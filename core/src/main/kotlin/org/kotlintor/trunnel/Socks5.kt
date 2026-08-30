package org.kotlintor.trunnel

/**
 * SOCKS5 trunnel / wire helpers (C Tor `socks5.c`).
 *
 * Inventory: `L1:trunnel/socks5.c`
 *
 * Runtime: [org.kotlintor.net.Socks5Extended].
 */
object Socks5 {
    const val VERSION: Int = 5
    const val CMD_CONNECT: Int = 1
    fun versionOk(v: Int): Boolean = v == VERSION
}
