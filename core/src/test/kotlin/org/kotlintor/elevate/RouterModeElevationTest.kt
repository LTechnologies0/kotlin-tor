package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.ClientRuntimeOptions
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.relay.RouterMode
import java.nio.file.Path

/**
 * Elevates `L1:feature/relay/routermode.c` toward D3.
 *
 * Evidence: server/public/advertised latch + dir_server_mode DirCache/DirPort.
 */
class RouterModeElevationTest {
    @TempDir
    lateinit var dataDir: Path

    @Test
    fun `server_mode and public_server_mode`() {
        val client = TorConfig(dataDirectory = dataDir)
        assertFalse(RouterMode.serverMode(client))
        val relay = TorConfig(
            dataDirectory = dataDir,
            clientOnly = false,
            orPort = ListenSpec("0.0.0.0", 9001),
        )
        assertTrue(RouterMode.serverMode(relay))
        assertTrue(RouterMode.publicServerMode(relay))
        val bridge = relay.copy(bridgeRelay = true)
        assertFalse(RouterMode.publicServerMode(bridge))
    }

    @Test
    fun `set_server_advertised latch`() {
        RouterMode.setAdvertisedServerMode(null)
        RouterMode.setServerAdvertised(false)
        assertFalse(RouterMode.advertisedServerMode())
        RouterMode.setServerAdvertised(true)
        assertTrue(RouterMode.advertisedServerMode())
        RouterMode.setServerAdvertised(false)
    }

    @Test
    fun `dir_server_mode DirCache DirPort bandwidth`() {
        val base = TorConfig(
            dataDirectory = dataDir,
            clientOnly = false,
            orPort = ListenSpec("0.0.0.0", 9001),
            runtime = ClientRuntimeOptions(dirCache = true),
        )
        assertTrue(RouterMode.dirServerMode(base))
        assertFalse(RouterMode.dirServerMode(base, hasBandwidthToBeDirserver = false))
        val noCache = base.copy(runtime = ClientRuntimeOptions(dirCache = false))
        assertFalse(RouterMode.dirServerMode(noCache))
        val dirPortOnly = TorConfig(
            dataDirectory = dataDir,
            dirPort = ListenSpec("0.0.0.0", 9030),
            runtime = ClientRuntimeOptions(dirCache = true),
        )
        assertTrue(RouterMode.dirServerMode(dirPortOnly))
    }
}
