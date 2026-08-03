package org.kotlintor.proxy

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kotlintor.TorClient
import org.kotlintor.net.BytePipe
import org.kotlintor.net.ExitDialer
import org.kotlintor.net.SocketBytePipe
import org.kotlintor.net.TorStreamBytePipe
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/** Production dialer: TorClient → RELAY BEGIN / RESOLVE. */
class TorClientDialer(private val client: TorClient) : ExitDialer {
    override suspend fun connect(
        host: String,
        port: Int,
        isolationKey: String?,
        clientAddr: String?,
        optimisticData: Boolean,
    ): BytePipe = TorStreamBytePipe(
        client.connect(host, port, isolationKey, clientAddr, optimisticData),
    )

    override suspend fun resolve(hostname: String): List<String> = client.resolve(hostname)
}

/**
 * Test / clearnet dialer: direct TCP (and InetAddress DNS).
 * Validates proxy handshakes + splice without live Tor.
 */
class ClearnetExitDialer : ExitDialer {
    override suspend fun connect(
        host: String,
        port: Int,
        isolationKey: String?,
        clientAddr: String?,
        optimisticData: Boolean,
    ): BytePipe = withContext(Dispatchers.IO) {
        val sock = Socket()
        sock.tcpNoDelay = true
        sock.connect(InetSocketAddress(host, port), 10_000)
        SocketBytePipe(sock)
    }

    override suspend fun resolve(hostname: String): List<String> = withContext(Dispatchers.IO) {
        InetAddress.getAllByName(hostname).map { it.hostAddress }.filterNotNull()
    }
}
