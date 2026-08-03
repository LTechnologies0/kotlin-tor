package org.kotlintor.cli

import org.kotlintor.TorDaemon
import org.kotlintor.config.TorConfig
import java.nio.file.Path

suspend fun runDebugHsConnect(
    dataDir: Path,
    onion: String,
    port: Int = 80,
) {
    val config = TorConfig(dataDirectory = dataDir)
    val daemon = TorDaemon(config)
    try {
        daemon.start(buildCircuit = true)
        println(daemon.client.bootstrapTracker.statusLine)
        println("connecting to $onion:$port via INTRODUCE/RENDEZVOUS…")
        val stream = daemon.client.connect(onion, port)
        try {
            val req =
                "GET / HTTP/1.0\r\n" +
                    "Host: ${onion.removeSuffix(".onion").lowercase()}.onion\r\n" +
                    "User-Agent: kotlin-tor/0.1\r\n" +
                    "\r\n"
            stream.write(req.toByteArray())
            val resp = stream.readHttpResponse(maxBytes = 64 * 1024)
            val text = resp.decodeToString()
            println("--- response (${resp.size} bytes) ---")
            println(text.take(800))
            check(text.contains("HTTP/1.")) { "no HTTP response from onion" }
            println("HS CONNECT OK")
        } finally {
            runCatching { stream.close() }
        }
    } finally {
        daemon.stop()
    }
}
