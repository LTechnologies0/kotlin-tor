package org.kotlintor.dir

import org.kotlintor.circuit.CircuitExtensions

/**
 * Subprotocol versioning (C Tor `protover.c` / `protover.h`).
 *
 * Inventory: `L1:core/or/protover.c`
 */
object Protover {
    enum class ProtocolType(val wireName: String, val id: Int) {
        LINK("Link", CircuitExtensions.ProtoId.LINK),
        LINK_AUTH("LinkAuth", CircuitExtensions.ProtoId.LINK_AUTH),
        RELAY("Relay", CircuitExtensions.ProtoId.RELAY),
        DIR_CACHE("DirCache", CircuitExtensions.ProtoId.DIR_CACHE),
        HS_DIR("HSDir", CircuitExtensions.ProtoId.HS_DIR),
        HS_INTRO("HSIntro", CircuitExtensions.ProtoId.HS_INTRO),
        HS_REND("HSRend", CircuitExtensions.ProtoId.HS_REND),
        DESC("Desc", CircuitExtensions.ProtoId.DESC),
        MICRODESC("Microdesc", CircuitExtensions.ProtoId.MICRODESC),
        CONS("Cons", CircuitExtensions.ProtoId.CONS),
        PADDING("Padding", CircuitExtensions.ProtoId.PADDING),
        FLOW_CTRL("FlowCtrl", CircuitExtensions.ProtoId.FLOW_CTRL),
        CONFLUX("Conflux", CircuitExtensions.ProtoId.CONFLUX),
        ;

        companion object {
            fun fromName(name: String): ProtocolType? =
                entries.firstOrNull { it.wireName.equals(name, ignoreCase = true) }
        }
    }

    /**
     * C Tor `protover_get_supported_protocols` — kotlin-tor advertises a modern subset
     * aligned with current client/relay needs (Link/Relay/FlowCtrl/Conflux/…).
     */
    const val SUPPORTED_PROTOCOLS: String =
        "Link=3-5 LinkAuth=3 Relay=1-6 DirCache=2 HSDir=2 HSIntro=4-5 HSRend=2 " +
            "Desc=1-2 Microdesc=1-2 Cons=1-2 Padding=2 FlowCtrl=1-2 Conflux=1"

    fun getSupportedProtocols(): String = SUPPORTED_PROTOCOLS

    fun getSupported(type: ProtocolType): String? {
        val map = parseProtocolList(SUPPORTED_PROTOCOLS)
        return map[type.wireName]
    }

    /** Parse `Link=3-5 Relay=1-6 …` into name → version-range string. */
    fun parseProtocolList(list: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (tok in list.trim().split(Regex("\\s+"))) {
            if (tok.isEmpty()) continue
            val eq = tok.indexOf('=')
            if (eq <= 0) continue
            out[tok.substring(0, eq)] = tok.substring(eq + 1)
        }
        return out
    }

    /** C Tor `protocol_list_supports_protocol`. */
    fun listSupportsProtocol(list: String, type: ProtocolType, version: Int): Boolean {
        val ranges = parseProtocolList(list)[type.wireName] ?: return false
        return versionInRanges(ranges, version)
    }

    /** C Tor `protocol_list_supports_protocol_or_later`. */
    fun listSupportsProtocolOrLater(list: String, type: ProtocolType, version: Int): Boolean {
        val ranges = parseProtocolList(list)[type.wireName] ?: return false
        return maxVersion(ranges) >= version
    }

    fun supports(type: ProtocolType, version: Int): Boolean =
        listSupportsProtocol(SUPPORTED_PROTOCOLS, type, version)

    fun versionInRanges(ranges: String, version: Int): Boolean {
        for (part in ranges.split(',')) {
            val t = part.trim()
            if (t.contains('-')) {
                val a = t.substringBefore('-').toIntOrNull() ?: continue
                val b = t.substringAfter('-').toIntOrNull() ?: continue
                if (version in a..b) return true
            } else if (t.toIntOrNull() == version) {
                return true
            }
        }
        return false
    }

    fun maxVersion(ranges: String): Int {
        var max = -1
        for (part in ranges.split(',')) {
            val t = part.trim()
            if (t.contains('-')) {
                val b = t.substringAfter('-').toIntOrNull() ?: continue
                if (b > max) max = b
            } else {
                val v = t.toIntOrNull() ?: continue
                if (v > max) max = v
            }
        }
        return max
    }

    /** C Tor `encode_protocol_list`. */
    fun encodeProtocolList(entries: Map<String, String>): String =
        entries.entries.joinToString(" ") { (k, v) -> "$k=$v" }

    fun encodeProtocolList(list: String): String = list.trim()

    /** C Tor `parse_protocol_list`. */
    fun parseProtocolListAlias(list: String): Map<String, String> = parseProtocolList(list)

    /** C Tor `protocol_list_supports_protocol`. */
    fun protocolListSupportsProtocol(list: String, type: ProtocolType, version: Int): Boolean =
        listSupportsProtocol(list, type, version)

    /** C Tor `protocol_list_supports_protocol_or_later`. */
    fun protocolListSupportsProtocolOrLater(list: String, type: ProtocolType, version: Int): Boolean =
        listSupportsProtocolOrLater(list, type, version)

    /** C Tor `protocol_type_to_str`. */
    fun protocolTypeToStr(type: ProtocolType): String = type.wireName

    /** C Tor `str_to_protocol_type`. */
    fun strToProtocolType(name: String): ProtocolType? = ProtocolType.fromName(name)

    /** C Tor `protover_get_supported_protocols`. */
    fun protoverGetSupportedProtocols(): String = getSupportedProtocols()

    /** C Tor `protover_get_supported`. */
    fun protoverGetSupported(type: ProtocolType): String? = getSupported(type)

    /** C Tor `protover_is_supported_here`. */
    fun protoverIsSupportedHere(type: ProtocolType, version: Int): Boolean =
        supports(type, version)

    /** C Tor `protover_list_is_invalid`. */
    fun protoverListIsInvalid(list: String): Boolean {
        for (tok in list.trim().split(Regex("\\s+"))) {
            if (tok.isEmpty()) continue
            if (!tok.contains('=')) return true
            val name = tok.substringBefore('=')
            if (ProtocolType.fromName(name) == null && name !in parseProtocolList(SUPPORTED_PROTOCOLS)) {
                // unknown names allowed in votes; only reject empty ranges
                if (tok.substringAfter('=').isEmpty()) return true
            }
        }
        return false
    }

    /** C Tor `protover_all_supported` — every entry in [list] is supported here. */
    fun protoverAllSupported(list: String): Boolean {
        for ((name, ranges) in parseProtocolList(list)) {
            val type = ProtocolType.fromName(name) ?: continue
            val max = maxVersion(ranges)
            if (max >= 0 && !supports(type, max)) return false
        }
        return true
    }

    /** C Tor `protover_compute_for_old_tor`. */
    fun protoverComputeForOldTor(): String = "Link=1-3 Relay=1-2"

    /** C Tor recommended/required protocol strings (static modern defaults). */
    fun protoverGetRecommendedClientProtocols(): String = SUPPORTED_PROTOCOLS
    fun protoverGetRecommendedRelayProtocols(): String = SUPPORTED_PROTOCOLS
    fun protoverGetRequiredClientProtocols(): String = "Link=4 LinkAuth=3 Relay=2"
    fun protoverGetRequiredRelayProtocols(): String = "Link=4 LinkAuth=3 Relay=2 DirCache=2"

    /** C Tor `protover_compute_vote` — intersection-ish: keep tokens present in all. */
    fun protoverComputeVote(lists: List<String>): String {
        if (lists.isEmpty()) return ""
        var acc = parseProtocolList(lists.first())
        for (l in lists.drop(1)) {
            val other = parseProtocolList(l)
            acc = acc.filterKeys { it in other }
                .mapValues { (k, v) ->
                    val a = maxVersion(v)
                    val b = maxVersion(other[k]!!)
                    "1-${minOf(a, b).coerceAtLeast(1)}"
                }
        }
        return encodeProtocolList(acc)
    }

    /** C Tor `protover_free_all` / `proto_entry_free_`. */
    fun protoverFreeAll() = Unit
    fun protoEntryFree_() = Unit
}
