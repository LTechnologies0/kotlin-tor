package org.kotlintor.dir

/**
 * Networkstatus parse (C Tor `ns_parse.c`).
 *
 * Inventory: `L1:feature/dirparse/ns_parse.c`
 */
object NsParse {
    fun looksLikeConsensus(text: String): Boolean =
        text.contains("network-status-version") && text.contains("vote-status")
}
