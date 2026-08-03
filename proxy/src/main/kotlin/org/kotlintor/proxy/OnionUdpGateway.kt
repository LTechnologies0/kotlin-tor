package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import org.kotlintor.config.HiddenServicePort
import org.kotlintor.config.ListenSpec

/**
 * Host [UdpTorGatewayServer] so SOCKS UDP ASSOCIATE can reach it via Tor TCP
 * (including as an onion virtual-port target).
 *
 * Native Tor UDP exit remains unavailable; this is the supported tunnel path.
 */
object OnionUdpGateway {
    data class Hosted(
        val gateway: UdpTorGatewayServer,
        /** Local TCP bind of the gateway. */
        val listenHost: String,
        val listenPort: Int,
        /**
         * Suggested HiddenServicePort: virtual [onionVirtualPort] → local gateway.
         * Publish with ADD_ONION / OnionService using this mapping.
         */
        val onionPort: HiddenServicePort,
    )

    /**
     * @param onionVirtualPort virtual port advertised on the onion address
     *   (clients CONNECT to `*.onion:onionVirtualPort` over Tor TCP).
     */
    fun start(
        scope: CoroutineScope,
        listen: ListenSpec = ListenSpec("127.0.0.1", 0),
        onionVirtualPort: Int = 9053,
    ): Hosted {
        val gw = UdpTorGatewayServer(scope)
        gw.start(listen)
        val port = gw.boundPort()
        require(port > 0) { "UdpTorGateway failed to bind" }
        val host = listen.host
        return Hosted(
            gateway = gw,
            listenHost = host,
            listenPort = port,
            onionPort = HiddenServicePort(onionVirtualPort, "$host:$port"),
        )
    }
}
