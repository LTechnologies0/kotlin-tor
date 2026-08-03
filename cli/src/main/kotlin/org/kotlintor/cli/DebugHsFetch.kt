package org.kotlintor.cli

import org.kotlintor.TorDaemon
import org.kotlintor.config.TorConfig
import java.nio.file.Files
import java.nio.file.Path

suspend fun runDebugHsFetch(
    data: Path,
    onion: String,
    viaNickname: String? = null,
    viaIp: String? = null,
    viaOrPort: Int? = null,
    viaFp: String? = null,
) {
    val daemon = TorDaemon(TorConfig(dataDirectory = data))
    try {
        daemon.start(buildCircuit = false)
        println("fetching descriptor for $onion ...")
        if (viaIp != null && viaOrPort != null && viaFp != null) {
            val nick = viaNickname ?: "debugHsDir"
            println("via relay $nick $viaIp:$viaOrPort fp=$viaFp")
            val raw = daemon.client.fetchOnionDescriptorViaRelay(onion, nick, viaIp, viaOrPort, viaFp)
            Files.writeString(data.resolve("last-hs-descriptor.txt"), raw)
            println("descriptor bytes=${raw.length} (saved; decrypt via normal fetch path)")
            println(raw.lineSequence().take(12).joinToString("\n"))
            return
        }
        if (viaNickname != null) {
            val raw = daemon.client.fetchOnionDescriptorVia(onion, viaNickname)
            Files.writeString(data.resolve("last-hs-descriptor.txt"), raw)
            println("descriptor bytes=${raw.length}")
            println(raw.lineSequence().take(12).joinToString("\n"))
            return
        }
        val fetched = daemon.client.fetchAndDecryptOnionDescriptor(onion)
        Files.writeString(data.resolve("last-hs-descriptor.txt"), fetched.outerText)
        Files.writeString(data.resolve("last-hs-inner.txt"), fetched.inner.raw)
        println("descriptor bytes=${fetched.outerText.length}")
        println("decrypted intro_points=${fetched.inner.introductionPoints.size}")
        println("create2-formats=${fetched.inner.create2Formats}")
        println("period=${fetched.period.intervalNum}")
        println(fetched.outerText.lineSequence().take(10).joinToString("\n"))
        if (fetched.inner.introductionPoints.isNotEmpty()) {
            val ip = fetched.inner.introductionPoints.first()
            println(
                "intro[0] link_spec_len=${ip.linkSpecifiers.size} " +
                    "ntor=${ip.onionKeyNtor.joinToString("") { "%02x".format(it) }.take(16)}…",
            )
        }
    } finally {
        daemon.stop()
    }
}
