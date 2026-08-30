package org.kotlintor.dir

/**
 * Router info view (C Tor `routerinfo.c`).
 *
 * Inventory: `L1:feature/nodelist/routerinfo.c`
 */
object RouterInfo {
    fun nickname(r: RouterStatus): String = r.nickname
    fun fingerprint(r: RouterStatus): String = r.fingerprintHex
    fun isRunning(r: RouterStatus): Boolean = r.isRunning
}
