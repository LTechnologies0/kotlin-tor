package org.kotlintor.net

/**
 * Address form matching SOCKS ATYP / Tor BEGIN targets.
 * Pure data — no DNS side effects.
 */
sealed class NetEndpoint {
    abstract val port: Int
    abstract fun hostString(): String

    data class Ipv4(val octets: ByteArray, override val port: Int) : NetEndpoint() {
        init {
            require(octets.size == 4)
            require(port in 0..65535)
        }

        override fun hostString(): String = octets.joinToString(".") { (it.toInt() and 0xff).toString() }

        override fun equals(other: Any?): Boolean =
            other is Ipv4 && port == other.port && octets.contentEquals(other.octets)

        override fun hashCode(): Int = 31 * octets.contentHashCode() + port
    }

    data class Ipv6(val octets: ByteArray, override val port: Int) : NetEndpoint() {
        init {
            require(octets.size == 16)
            require(port in 0..65535)
        }

        override fun hostString(): String =
            java.net.InetAddress.getByAddress(octets).hostAddress

        override fun equals(other: Any?): Boolean =
            other is Ipv6 && port == other.port && octets.contentEquals(other.octets)

        override fun hashCode(): Int = 31 * octets.contentHashCode() + port
    }

    data class Domain(val name: String, override val port: Int) : NetEndpoint() {
        init {
            require(name.isNotEmpty() && name.length <= 255)
            require(port in 0..65535)
        }

        override fun hostString(): String = name
    }

    companion object {
        fun domain(host: String, port: Int): Domain = Domain(host, port)

        fun parseHostPort(host: String, port: Int): NetEndpoint {
            val h = host.trim().removePrefix("[").removeSuffix("]")
            return when {
                h.count { it == '.' } == 3 && h.all { it.isDigit() || it == '.' } -> {
                    val parts = h.split('.')
                    if (parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }) {
                        Ipv4(byteArrayOf(
                            parts[0].toInt().toByte(),
                            parts[1].toInt().toByte(),
                            parts[2].toInt().toByte(),
                            parts[3].toInt().toByte(),
                        ), port)
                    } else Domain(h, port)
                }
                h.contains(':') -> {
                    runCatching {
                        Ipv6(java.net.InetAddress.getByName(h).address, port)
                    }.getOrElse { Domain(h, port) }
                }
                else -> Domain(h, port)
            }
        }
    }
}

/** IP family preference for Tor BEGIN (prop365 X-Tor-Family-Preference). */
enum class FamilyPreference(val wire: String) {
    Ipv4Preferred("ipv4-preferred"),
    Ipv6Preferred("ipv6-preferred"),
    Ipv4Only("ipv4-only"),
    Ipv6Only("ipv6-only"),
    ;

    companion object {
        fun parse(raw: String?): FamilyPreference {
            if (raw == null) return Ipv4Preferred
            return entries.firstOrNull { it.wire.equals(raw.trim(), ignoreCase = true) }
                ?: Ipv4Preferred
        }
    }
}
