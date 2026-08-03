package org.kotlintor.cli

import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.delay
import org.kotlintor.TorDaemon
import org.kotlintor.config.HiddenServiceConfig
import org.kotlintor.config.HiddenServicePort
import org.kotlintor.config.TorConfig
import java.net.InetSocketAddress
import java.nio.file.Path

/**
 * Long-running HS host: local HTTP backend + ESTABLISH_INTRO + publish + INTRODUCE2 listen.
 * Leave running while another process runs debug-hsconnect against the printed .onion.
 */
suspend fun runDebugHsHost(dataDir: Path, backendPort: Int = 18080) {
    val backend = HttpServer.create(InetSocketAddress("127.0.0.1", backendPort), 0)
    backend.createContext("/") { exch ->
        val body = "kotlin-tor hs host ok\n".toByteArray()
        exch.responseHeaders.add("Content-Type", "text/plain")
        exch.sendResponseHeaders(200, body.size.toLong())
        exch.responseBody.use { it.write(body) }
    }
    backend.executor = null
    backend.start()
    println("local backend http://127.0.0.1:$backendPort/")

    val hsDir = dataDir.resolve("hs/host")
    val config = TorConfig(
        dataDirectory = dataDir,
        hiddenServices = emptyList(),
    )
    val daemon = TorDaemon(config)
    try {
        daemon.start(buildCircuit = true)
        println(daemon.client.bootstrapTracker.statusLine)
        val inst = daemon.onionServices.addOnion(
            ports = listOf(80 to "127.0.0.1:$backendPort"),
            directory = hsDir,
        )
        println("service ${inst.address}")
        daemon.onionServices.establishIntroPoints(inst, n = 2)
        println("intro_points=${inst.introPoints.size}")
        val uploaded = daemon.onionServices.publish(inst)
        println("HSDirs_uploaded=$uploaded")
        println("HS HOST READY ${inst.address}")
        println("Connect with: kotlin-tor debug-hsconnect --data <other-dir> --onion ${inst.address}")
        // Keep intros + INTRODUCE2 listeners alive.
        while (true) {
            delay(60_000)
            println("HS host heartbeat intros=${inst.introPoints.size} listening")
        }
    } finally {
        daemon.stop()
        backend.stop(0)
    }
}
