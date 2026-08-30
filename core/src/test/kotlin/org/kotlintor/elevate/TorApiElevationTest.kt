package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.api.TorApi
import org.kotlintor.api.TorMainConfiguration
import java.nio.file.Path

/**
 * Elevates `L1:feature/api/tor_api.c` D2→D3.
 *
 * Evidence: tor_main_configuration_new/set_command_line/setup_control_socket/free,
 * tor_api_get_provider_version, tor_run_main ownership, tor_main.
 */
class TorApiElevationTest {
    @Test
    fun `provider version and configuration ownership`(@TempDir dir: Path) {
        assertEquals("tor 0.1.0-SNAPSHOT", TorApi.providerVersion())
        val cfg = TorApi.newConfiguration()
        cfg.dataDirectory = dir
        assertEquals(0, cfg.setCommandLine(arrayOf("tor", "SocksPort", "0", "DisableNetwork", "1")))
        assertEquals(5, cfg.argc)
        val fd = cfg.setupControlSocket()
        assertNotEquals(TorMainConfiguration.INVALID_CONTROL_SOCKET, fd)
        assertEquals(fd, cfg.owningControllerSocket)
        assertEquals(listOf("__OwningControllerFD", fd.toString()), cfg.ownedArguments())
        // Second setup must fail like C Tor when socket already OK.
        assertEquals(TorMainConfiguration.INVALID_CONTROL_SOCKET, cfg.setupControlSocket())
        val built = cfg.buildConfig()
        assertEquals(fd, built.process.owningControllerFd)
        assertEquals(0, TorApi.runMain(cfg, dryRun = true))
        cfg.free()
        assertEquals(TorMainConfiguration.INVALID_CONTROL_SOCKET, cfg.owningControllerSocket)
    }

    @Test
    fun `tor_main dry-run path`(@TempDir dir: Path) {
        val rv = TorApi.main(
            arrayOf("tor", "DataDirectory", dir.toString(), "SocksPort", "0", "DisableNetwork", "1"),
            dryRun = true,
        )
        assertEquals(0, rv)
    }
}
