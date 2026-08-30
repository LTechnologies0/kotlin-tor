package org.kotlintor.proxy

import org.kotlintor.config.TorConfig

/**
 * Proxy mode detection (C Tor `proxymode.c`).
 *
 * Inventory: `L1:feature/client/proxymode.c`
 */
object ProxyMode {
    fun socksEnabled(config: TorConfig): Boolean = config.socksPorts.isNotEmpty()

    fun httpTunnelEnabled(config: TorConfig): Boolean = config.httpTunnelPort != null

    fun dnsPortEnabled(config: TorConfig): Boolean = config.dnsPort != null

    fun anyClientProxy(config: TorConfig): Boolean =
        socksEnabled(config) || httpTunnelEnabled(config) || dnsPortEnabled(config)

    /**
     * C Tor `proxy_mode` — true iff any client AP listener is configured
     * (SocksPort / TransPort / DNSPort / NATDPort; HTTPTunnel treated as AP).
     */
    fun proxyMode(config: TorConfig): Boolean =
        anyClientProxy(config) ||
            config.transPort != null ||
            config.process.natdPort != null
}
