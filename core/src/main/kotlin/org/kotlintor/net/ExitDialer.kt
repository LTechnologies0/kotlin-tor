package org.kotlintor.net

/**
 * Abstraction over Tor exit (or clearnet test) dials used by all proxy frontends.
 * Production: [org.kotlintor.proxy.TorClientDialer]. Tests: [ClearnetExitDialer].
 */
interface ExitDialer {
    suspend fun connect(
        host: String,
        port: Int,
        isolationKey: String? = null,
        clientAddr: String? = null,
        optimisticData: Boolean = true,
    ): BytePipe

    /** DNS via RELAY RESOLVE (or clearnet InetAddress for tests). */
    suspend fun resolve(hostname: String): List<String> = emptyList()
}
