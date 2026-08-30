package org.kotlintor.dir

/**
 * Directory server / measured-bw cache surface (C Tor `dirserv.c`).
 *
 * Inventory: `L1:feature/dircache/dirserv.c`
 *
 * Measured bandwidth cache: [MeasuredBwCache]; trusted dirs: [DirList].
 */
object DirServ {
    fun measuredBwCache(): MeasuredBwCache = MeasuredBwCache()
    fun trustedList(): DirList = DirList()
}
