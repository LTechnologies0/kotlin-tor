package org.kotlintor.net

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * FascistFirewall / Reachable* / FirewallPorts policy (C Tor `policies.c`).
 *
 * Patterns: `*`, `*:port`, `*:port-port`, `addr`, `addr:port`, `addr:*`, CIDR `a.b.c.d/n:ports`.
 * Naming-aligned entry: [Policies].
 */
class AddrPolicy(private val rules: List<Rule>) {
    data class Rule(
        val accept: Boolean,
        val host: HostPat,
        val portMin: Int,
        val portMax: Int,
    )

    sealed class HostPat {
        data object Any : HostPat()
        data class Exact(val addr: InetAddress) : HostPat()
        data class Cidr(val network: InetAddress, val prefix: Int) : HostPat()
    }

    fun allows(host: String, port: Int): Boolean {
        if (port !in 0..65535) return false
        val addrs = runCatching { InetAddress.getAllByName(host) }.getOrNull() ?: return false
        return addrs.any { allows(it, port) }
    }

    fun allows(addr: InetAddress, port: Int): Boolean {
        if (rules.isEmpty()) return true
        for (r in rules) {
            if (port !in r.portMin..r.portMax) continue
            if (!matchHost(r.host, addr)) continue
            return r.accept
        }
        // C Tor FascistFirewall: default reject when rules present
        return false
    }

    private fun matchHost(pat: HostPat, addr: InetAddress): Boolean =
        when (pat) {
            HostPat.Any -> true
            is HostPat.Exact -> addr.address.contentEquals(pat.addr.address)
            is HostPat.Cidr -> inCidr(addr, pat.network, pat.prefix)
        }

    companion object {
        fun allowAll(): AddrPolicy = AddrPolicy(emptyList())

        /** FascistFirewall=1 with FirewallPorts → accept *:port for each port, else reject. */
        fun fascist(firewallPorts: Set<Int>): AddrPolicy {
            if (firewallPorts.isEmpty()) {
                return AddrPolicy(listOf(Rule(true, HostPat.Any, 80, 80), Rule(true, HostPat.Any, 443, 443)))
            }
            return AddrPolicy(
                firewallPorts.map { Rule(true, HostPat.Any, it, it) },
            )
        }

        fun parseLines(lines: List<String>): AddrPolicy {
            if (lines.isEmpty()) return allowAll()
            return AddrPolicy(lines.map { parseRule(it) })
        }

        fun parseRule(raw: String): Rule {
            val t = raw.trim()
            val accept = when {
                t.startsWith("accept", true) -> true
                t.startsWith("reject", true) -> false
                else -> true // bare addr:port means accept
            }
            val rest = if (t.startsWith("accept", true) || t.startsWith("reject", true)) {
                t.substringAfter(' ').trim()
            } else {
                t
            }
            val colon = rest.lastIndexOf(':')
            val (hostPart, portPart) = if (colon < 0) {
                rest to "*"
            } else {
                rest.substring(0, colon) to rest.substring(colon + 1)
            }
            val (pMin, pMax) = parsePorts(portPart)
            return Rule(accept, parseHost(hostPart), pMin, pMax)
        }

        private fun parsePorts(s: String): Pair<Int, Int> {
            if (s == "*") return 0 to 65535
            val dash = s.indexOf('-')
            return if (dash < 0) {
                val p = s.toInt()
                p to p
            } else {
                s.substring(0, dash).toInt() to s.substring(dash + 1).toInt()
            }
        }

        private fun parseHost(s: String): HostPat =
            when {
                s == "*" || s.isEmpty() -> HostPat.Any
                '/' in s -> {
                    val net = InetAddress.getByName(s.substringBefore('/'))
                    val prefix = s.substringAfter('/').toInt()
                    HostPat.Cidr(net, prefix)
                }
                else -> HostPat.Exact(InetAddress.getByName(s))
            }

        private fun inCidr(addr: InetAddress, network: InetAddress, prefix: Int): Boolean {
            val a = addr.address
            val n = network.address
            if (a.size != n.size) return false
            var bits = prefix
            var i = 0
            while (bits >= 8 && i < a.size) {
                if (a[i] != n[i]) return false
                i++
                bits -= 8
            }
            if (bits == 0 || i >= a.size) return true
            val mask = (0xff shl (8 - bits)) and 0xff
            return (a[i].toInt() and mask) == (n[i].toInt() and mask)
        }
    }
}

/**
 * OutboundBindAddress* helpers (C Tor bind-before-connect path).
 */
object OutboundBind {
    fun bindBeforeConnect(sock: Socket, localHost: String?) {
        if (localHost.isNullOrBlank()) return
        val local = InetAddress.getByName(localHost)
        sock.bind(InetSocketAddress(local, 0))
    }

    /**
     * Create a socket, optionally [protect] it from VPN capture, bind, then connect.
     * Protect runs immediately after [Socket] construction so the SYN is not routed into TUN.
     */
    fun connect(
        remoteHost: String,
        remotePort: Int,
        bindHost: String?,
        timeoutMs: Int = 15_000,
        /** ConstrainedSockets buffer size; null/≤0 skips. */
        constrainedSockSize: Int? = null,
        protect: Boolean = true,
        /**
         * Optional TCPProxy host:port — connect there first, then inject PROXY
         * header toward [remoteHost]:[remotePort] when [tcpProxyProtocol] is haproxy.
         */
        tcpProxyHost: String? = null,
        tcpProxyPort: Int? = null,
        tcpProxyProtocol: String = "haproxy",
    ): Socket {
        if (!tcpProxyHost.isNullOrBlank() && tcpProxyPort != null && tcpProxyPort > 0) {
            val sock = connectDirect(
                tcpProxyHost,
                tcpProxyPort,
                bindHost,
                timeoutMs,
                constrainedSockSize,
                protect,
            )
            if (tcpProxyProtocol.equals("haproxy", ignoreCase = true)) {
                HaproxyProxyHeader.injectAfterConnect(sock, remoteHost, remotePort)
            }
            return sock
        }
        return connectDirect(
            remoteHost,
            remotePort,
            bindHost,
            timeoutMs,
            constrainedSockSize,
            protect,
        )
    }

    private fun connectDirect(
        remoteHost: String,
        remotePort: Int,
        bindHost: String?,
        timeoutMs: Int,
        constrainedSockSize: Int?,
        protect: Boolean,
    ): Socket {
        val sock = Socket()
        if (protect) {
            // Allocate a local FD before SYN so SO_MARK / VpnService.protect can apply.
            if (!sock.isBound && org.kotlintor.os.PlatformNatives.hasSocketProtector()) {
                runCatching { sock.bind(InetSocketAddress(0)) }
            }
            val ok = org.kotlintor.os.PlatformNatives.protectSocket(sock)
            if (!ok && org.kotlintor.os.PlatformNatives.hasSocketProtector()) {
                runCatching { sock.close() }
                val detail = org.kotlintor.os.PlatformNatives.lastProtectFailure?.let { " ($it)" }.orEmpty()
                error("VPN protect failed before OR connect — refusing clearnet/TUN-loop dial$detail")
            }
        }
        bindBeforeConnect(sock, bindHost)
        if (constrainedSockSize != null && constrainedSockSize > 0) {
            val n = constrainedSockSize.coerceIn(512, 65536)
            runCatching {
                sock.receiveBufferSize = n
                sock.sendBufferSize = n
            }
        }
        sock.connect(InetSocketAddress(remoteHost, remotePort), timeoutMs)
        return sock
    }
}

/**
 * SafeSocks / WarnUnsafeSocks / TestSocks (C Tor socks policy helpers).
 * SafeSocks rejects IP-literal destinations (prefer hostname for DNS at exit).
 *
 * VPN / OnionTunnel profiles may set [allowIpLiterals] so fake-IP cookies and
 * direct IP exits work under TUN (onionmasq-class NI).
 */
object SafeSocksPolicy {
    fun isIpLiteral(host: String): Boolean {
        val h = host.trim().removePrefix("[").removeSuffix("]")
        if (h.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) return true
        if (':' in h) {
            return runCatching {
                val a = InetAddress.getByName(h)
                a is java.net.Inet6Address
            }.getOrDefault(false)
        }
        return false
    }

    fun allows(host: String, safeSocks: Boolean, allowIpLiterals: Boolean = false): Boolean {
        if (!safeSocks) return true
        if (allowIpLiterals) return true
        if (host.endsWith(".onion", ignoreCase = true)) return true
        return !isIpLiteral(host)
    }
}
