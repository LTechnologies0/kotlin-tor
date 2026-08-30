package org.kotlintor.relay

/**
 * Relay history / reputation counters (C Tor `rephist.c`).
 *
 * Inventory: `L1:feature/stats/rephist.c`
 */
object RepHist {
    data class CircHist(
        var nCreated: Long = 0,
        var nSucceeded: Long = 0,
        var nFailed: Long = 0,
        var bytesRead: Long = 0,
        var bytesWritten: Long = 0,
    )

    private val byRelay = java.util.concurrent.ConcurrentHashMap<String, CircHist>()

    fun forRelay(fpHex: String): CircHist =
        byRelay.getOrPut(fpHex.lowercase()) { CircHist() }

    fun noteCreate(fpHex: String) {
        forRelay(fpHex).nCreated++
    }

    fun noteSuccess(fpHex: String) {
        forRelay(fpHex).nSucceeded++
    }

    fun noteFailure(fpHex: String) {
        forRelay(fpHex).nFailed++
    }

    fun noteBytes(fpHex: String, read: Long, written: Long) {
        val h = forRelay(fpHex)
        h.bytesRead += read
        h.bytesWritten += written
    }

    fun clear() = byRelay.clear()
}
