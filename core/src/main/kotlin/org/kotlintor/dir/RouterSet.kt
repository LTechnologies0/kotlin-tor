package org.kotlintor.dir

import org.kotlintor.util.toHex
import java.net.InetAddress

/**
 * Router set (C Tor `routerset.c`).
 *
 * Inventory: `L1:feature/nodelist/routerset.c`
 */
class RouterSet(description: String = "") {
    private val names = HashSet<String>()
    private val digests = HashSet<String>()
    private val countries = HashSet<String>()
    private val policies = ArrayList<AddrPolicy>()
    var description: String = description
        private set

    data class AddrPolicy(val network: ByteArray, val prefixLen: Int) {
        fun matches(ip: ByteArray): Boolean {
            if (ip.size != network.size) return false
            val full = prefixLen / 8
            val rem = prefixLen % 8
            for (i in 0 until full) if (ip[i] != network[i]) return false
            if (rem == 0) return true
            val mask = (0xff shl (8 - rem)) and 0xff
            return (ip[full].toInt() and mask) == (network[full].toInt() and mask)
        }
    }

    fun parse(s: String): RouterSet {
        for (tok in s.split(',').map { it.trim() }.filter { it.isNotEmpty() }) {
            when {
                tok.startsWith("{") && tok.endsWith("}") ->
                    countries += tok.substring(1, tok.length - 1).lowercase()
                tok.startsWith("$") ->
                    digests += tok.drop(1).lowercase().replace(" ", "")
                tok.contains('/') && tok[0].isDigit() -> {
                    val (addr, plen) = tok.split('/', limit = 2)
                    val ip = InetAddress.getByName(addr).address
                    policies += AddrPolicy(ip, plen.toInt())
                }
                tok.matches(Regex("[0-9A-Fa-f]{40}")) ->
                    digests += tok.lowercase()
                else -> names += tok.lowercase()
            }
        }
        return this
    }

    fun isEmpty(): Boolean =
        names.isEmpty() && digests.isEmpty() && countries.isEmpty() && policies.isEmpty()

    fun contains(
        nickname: String?,
        identityHex: String?,
        ip: String?,
        country: String? = null,
    ): Boolean {
        if (isEmpty()) return false
        if (nickname != null && nickname.lowercase() in names) return true
        if (identityHex != null && identityHex.lowercase().replace(" ", "") in digests) return true
        if (country != null && country.lowercase() in countries) return true
        if (ip != null && policies.isNotEmpty()) {
            val bytes = runCatching { InetAddress.getByName(ip).address }.getOrNull()
            if (bytes != null && policies.any { it.matches(bytes) }) return true
        }
        return false
    }

    fun containsRouter(rs: RouterStatus, country: String? = null): Boolean =
        contains(rs.nickname, rs.fingerprintHex, rs.ip, country)

    fun toSetString(): String = buildList {
        addAll(names)
        digests.forEach { add("\$$it") }
        countries.forEach { add("{$it}") }
        policies.forEach {
            val host = InetAddress.getByAddress(it.network).hostAddress
            add("$host/${it.prefixLen}")
        }
    }.joinToString(",")

    companion object {
        fun parse(s: String, description: String = ""): RouterSet =
            RouterSet(description).parse(s)
    }
}
