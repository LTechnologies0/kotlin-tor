package org.kotlintor.pt

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
import java.nio.file.Files
import java.nio.file.Path

/**
 * Speaks a minimal pt-spec client handshake so PtManager can be tested without
 * a real obfs4/snowflake binary.
 */
class FakePtClientE2ETest {
    @TempDir
    lateinit var tmp: Path

    @Test
    fun `PtManager parses CMETHOD from fake PT binary`() {
        val script = tmp.resolve("fake-pt.sh")
        Files.writeString(
            script,
            """
            #!/bin/bash
            echo 'VERSION 1'
            echo 'CMETHOD obfs4 socks5 127.0.0.1:19999'
            echo 'CMETHODS DONE'
            sleep 2
            """.trimIndent(),
        )
        script.toFile().setExecutable(true)

        val torrc = """
            DataDirectory ${tmp.resolve("data")}
            UseBridges 1
            Bridge obfs4 1.2.3.4:443 FINGERPRINT cert=abcd iat-mode=0
            ClientTransportPlugin obfs4 exec $script
        """.trimIndent()
        val cfg = TorrcParser.parse(torrc, tmp.resolve("data"))
        val pt = PtManager(cfg)
        pt.start()
        assertEquals("127.0.0.1:19999", pt.socksAddress)
        assertEquals("127.0.0.1:19999", pt.cmethods["obfs4"]?.socksAddress)
        assertTrue(pt.validateConfiguredBridges().isEmpty())
        pt.stop()
    }

    @Test
    fun `PtServerManager parses SMETHOD from fake PT binary`() {
        val script = tmp.resolve("fake-pt-server.sh")
        Files.writeString(
            script,
            """
            #!/bin/bash
            echo 'VERSION 1'
            echo 'SMETHOD obfs4 0.0.0.0:4443 ARGS:cert=xx'
            echo 'SMETHODS DONE'
            sleep 2
            """.trimIndent(),
        )
        script.toFile().setExecutable(true)

        val cfg = TorConfig(
            dataDirectory = tmp.resolve("data"),
            clientOnly = false,
            orPort = org.kotlintor.config.ListenSpec("127.0.0.1", 9001),
            serverTransportPlugin = "obfs4 exec $script",
            serverTransportListenAddr = listOf("obfs4 0.0.0.0:4443"),
        )
        val srv = PtServerManager(cfg)
        srv.start()
        assertNotNull(srv.smethods["obfs4"])
        assertTrue(srv.smethods["obfs4"]!!.contains("0.0.0.0:4443"))
        srv.stop()
    }
}
