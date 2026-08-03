package org.kotlintor.cli

import kotlinx.coroutines.delay
import org.kotlintor.TorDaemon
import org.kotlintor.config.HiddenServiceConfig
import org.kotlintor.config.HiddenServicePort
import org.kotlintor.config.TorConfig
import java.nio.file.Path

/** Bootstrap, ESTABLISH_INTRO, then encrypt+publish HS descriptor to HSDirs. */
suspend fun runDebugHsIntro(dataDir: Path) {
    val hsDir = dataDir.resolve("hs/debug")
    val config = TorConfig(
        dataDirectory = dataDir,
        // Empty list: we drive establish+publish explicitly (avoids racing startAll).
        hiddenServices = emptyList(),
    )
    val daemon = TorDaemon(config)
    try {
        daemon.start(buildCircuit = true)
        println(daemon.client.bootstrapTracker.statusLine)
        val inst = daemon.onionServices.addOnion(
            ports = listOf(80 to "127.0.0.1:8080"),
            directory = hsDir,
        )
        println("service ${inst.address}")
        daemon.onionServices.establishIntroPoints(inst, n = 2)
        println("intro_points=${inst.introPoints.size}")
        for (ip in inst.introPoints) {
            println("  ${ip.relay.nickname} ${ip.relay.fingerprintHex}")
        }
        check(inst.introPoints.isNotEmpty()) { "no INTRO_ESTABLISHED" }
        val uploaded = daemon.onionServices.publish(inst)
        println("HSDirs_uploaded=$uploaded desc_bytes=${inst.lastDescriptor?.length}")
        // brief settle so logs flush
        delay(200)
        println("HS INTRO+PUBLISH OK")
    } finally {
        daemon.stop()
    }
}
