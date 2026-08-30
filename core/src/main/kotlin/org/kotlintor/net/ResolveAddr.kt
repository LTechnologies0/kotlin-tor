package org.kotlintor.net

import org.kotlintor.config.TorConfig
import org.kotlintor.relay.RelayFindAddr

/**
 * Address resolution / advertised address (C Tor `resolve_addr.c`).
 *
 * Inventory: `L1:app/config/resolve_addr.c`
 */
object ResolveAddr {
    enum class Family { IPV4, IPV6 }

    @Volatile private var suggestedV4: String? = null
    @Volatile private var suggestedV6: String? = null

    fun resetSuggested(family: Family? = null) {
        when (family) {
            Family.IPV4 -> suggestedV4 = null
            Family.IPV6 -> suggestedV6 = null
            null -> {
                suggestedV4 = null
                suggestedV6 = null
            }
        }
    }

    fun noteSuggested(addr: String) {
        if (addr.contains(':')) suggestedV6 = addr else suggestedV4 = addr
    }

    fun suggested(family: Family): String? = when (family) {
        Family.IPV4 -> suggestedV4
        Family.IPV6 -> suggestedV6
    }

    /** Prefer configured Address, then suggested, then [RelayFindAddr]. */
    fun resolveForPublish(config: TorConfig): Pair<String?, String?> {
        val (v4, v6) = RelayFindAddr.suggestAddresses(config)
        return (suggestedV4 ?: v4) to (suggestedV6 ?: v6)
    }
}
