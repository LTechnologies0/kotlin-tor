package org.kotlintor.relay

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Exit policy evaluator (torrc `ExitPolicy` / `accept` / `reject` lines).
 *
 * Rules are matched in order; first hit wins. Default when no rules match: reject.
 * Address patterns: `*`, IPv4, `a.b.c.d/mask`, `*4`, `*6`. Port: `*`, `N`, `N-M`.
 */
class ExitPolicy(
    private val rules: List<Rule>,
    private val rejectPrivate: Boolean = false,
    private val rejectLocalInterfaces: Boolean = false,
) {
    data class Rule(
        val accept: Boolean,
        val addr: AddrPattern,
        val portMin: Int,
        val portMax: Int,
    )

    sealed class AddrPattern {
        data object Any : AddrPattern()
        data object AnyV4 : AddrPattern()
        data object AnyV6 : AddrPattern()
        data class Cidr(val network: InetAddress, val prefix: Int) : AddrPattern()
        data class Exact(val address: InetAddress) : AddrPattern()
    }

    fun withRejectPrivate(on: Boolean): ExitPolicy =
        ExitPolicy(rules, rejectPrivate = on, rejectLocalInterfaces = rejectLocalInterfaces)

    fun withRejectLocalInterfaces(on: Boolean): ExitPolicy =
        ExitPolicy(rules, rejectPrivate = rejectPrivate, rejectLocalInterfaces = on)

    fun allows(host: String, port: Int): Boolean {
        if (port !in 1..65535) return false
        val addrs = runCatching { InetAddress.getAllByName(host) }.getOrNull() ?: return false
        return addrs.any { addr -> allows(addr, port) }
    }

    fun allows(addr: InetAddress, port: Int): Boolean {
        if (rejectPrivate && org.kotlintor.net.PrivateAddresses.isPrivate(addr)) return false
        if (rejectLocalInterfaces && isLocalInterface(addr)) return false
        for (r in rules) {
            if (port !in r.portMin..r.portMax) continue
            if (!matches(r.addr, addr)) continue
            return r.accept
        }
        return false
    }

    private fun isLocalInterface(addr: InetAddress): Boolean {
        if (addr.isAnyLocalAddress || addr.isLoopbackAddress) return true
        return runCatching {
            java.net.NetworkInterface.getNetworkInterfaces().toList().any { ni ->
                ni.inetAddresses.toList().any { it.address.contentEquals(addr.address) }
            }
        }.getOrDefault(false)
    }

    private fun matches(pat: AddrPattern, addr: InetAddress): Boolean =
        when (pat) {
            AddrPattern.Any -> true
            AddrPattern.AnyV4 -> addr is Inet4Address
            AddrPattern.AnyV6 -> addr is Inet6Address
            is AddrPattern.Exact -> addr.address.contentEquals(pat.address.address)
            is AddrPattern.Cidr -> inCidr(addr, pat.network, pat.prefix)
        }

    companion object {
        /** Safe default for relays that are not exits. */
        fun rejectAll(): ExitPolicy = ExitPolicy(listOf(parseRule("reject *:*")))

        /**
         * C Tor `ReducedExitPolicy 1` — common ports only, then reject *:*.
         * Matches tor's reduced_exit_policy (approx. current network defaults).
         */
        fun reduced(): ExitPolicy = fromTorrcLines(REDUCED_LINES)

        fun fromTorrcLines(lines: List<String>): ExitPolicy {
            if (lines.isEmpty()) return rejectAll()
            return ExitPolicy(lines.map { parseRule(it) })
        }

        private val REDUCED_LINES = listOf(
            "accept *:20-23",
            "accept *:43",
            "accept *:53",
            "accept *:79-81",
            "accept *:88",
            "accept *:110",
            "accept *:143",
            "accept *:194",
            "accept *:220",
            "accept *:389",
            "accept *:443",
            "accept *:464",
            "accept *:531",
            "accept *:543-544",
            "accept *:554",
            "accept *:563",
            "accept *:587",
            "accept *:636",
            "accept *:706",
            "accept *:749",
            "accept *:873",
            "accept *:902-904",
            "accept *:981",
            "accept *:989-995",
            "accept *:1194",
            "accept *:1220",
            "accept *:1293",
            "accept *:1500",
            "accept *:1533",
            "accept *:1677",
            "accept *:1723",
            "accept *:1755",
            "accept *:1863",
            "accept *:2082-2083",
            "accept *:2086-2087",
            "accept *:2095-2096",
            "accept *:2102-2104",
            "accept *:3128",
            "accept *:3389",
            "accept *:3690",
            "accept *:4321",
            "accept *:4643",
            "accept *:5050",
            "accept *:5190",
            "accept *:5222-5223",
            "accept *:5228",
            "accept *:5900",
            "accept *:6660-6669",
            "accept *:6679",
            "accept *:6697",
            "accept *:8000",
            "accept *:8008",
            "accept *:8080",
            "accept *:8087-8088",
            "accept *:8232-8233",
            "accept *:8332-8333",
            "accept *:8443",
            "accept *:8888",
            "accept *:9418",
            "accept *:9999",
            "accept *:10000",
            "accept *:11371",
            "accept *:19294",
            "accept *:19638",
            "accept *:50002",
            "accept *:64738",
            "reject *:*",
        )

        fun parseRule(raw: String): Rule {
            val t = raw.trim()
            val accept = when {
                t.startsWith("accept", ignoreCase = true) -> true
                t.startsWith("reject", ignoreCase = true) -> false
                else -> error("ExitPolicy rule must start with accept/reject: $raw")
            }
            val rest = t.substringAfter(' ').trim()
            val colon = rest.lastIndexOf(':')
            require(colon > 0) { "ExitPolicy missing port: $raw" }
            val addrPart = rest.substring(0, colon)
            val portPart = rest.substring(colon + 1)
            val (pMin, pMax) = parsePortRange(portPart)
            return Rule(accept, parseAddr(addrPart), pMin, pMax)
        }

        private fun parsePortRange(s: String): Pair<Int, Int> {
            if (s == "*") return 1 to 65535
            val dash = s.indexOf('-')
            return if (dash < 0) {
                val p = s.toInt()
                p to p
            } else {
                s.substring(0, dash).toInt() to s.substring(dash + 1).toInt()
            }
        }

        private fun parseAddr(s: String): AddrPattern =
            when (s) {
                "*" -> AddrPattern.Any
                "*4" -> AddrPattern.AnyV4
                "*6" -> AddrPattern.AnyV6
                else -> {
                    val slash = s.indexOf('/')
                    if (slash < 0) {
                        AddrPattern.Exact(InetAddress.getByName(s))
                    } else {
                        val net = InetAddress.getByName(s.substring(0, slash))
                        val prefix = s.substring(slash + 1).toInt()
                        AddrPattern.Cidr(net, prefix)
                    }
                }
            }

        private fun inCidr(addr: InetAddress, network: InetAddress, prefix: Int): Boolean {
            val a = addr.address
            val n = network.address
            if (a.size != n.size) return false
            val full = prefix / 8
            val rem = prefix % 8
            for (i in 0 until full) {
                if (a[i] != n[i]) return false
            }
            if (rem == 0) return true
            val mask = (0xff shl (8 - rem)) and 0xff
            return (a[full].toInt() and mask) == (n[full].toInt() and mask)
        }
    }
}
