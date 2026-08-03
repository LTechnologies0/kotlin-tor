package org.kotlintor.integration

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.kotlintor.TorDaemon
import org.kotlintor.config.TorConfig
import java.nio.file.Files

/**
 * Gated live-network test. Enable with: ./gradlew :integration-tests:test -Pkotlin.tor.liveNetwork=true
 */
class LiveBootstrapTest {
    @Test
    fun `bootstrap against live directory authorities`() = runBlocking {
        assumeTrue(System.getProperty("kotlin.tor.liveNetwork") == "true")
        val dir = Files.createTempDirectory("ktor-live")
        val daemon = TorDaemon(TorConfig(dataDirectory = dir))
        try {
            daemon.start()
            assertTrue(daemon.client.isBootstrapped)
            val c = daemon.client.consensusOrNull()
            assertTrue(c != null && c.relays.isNotEmpty())
        } finally {
            daemon.stop()
        }
    }
}
