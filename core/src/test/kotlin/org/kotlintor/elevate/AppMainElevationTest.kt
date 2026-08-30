package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.app.Main
import org.kotlintor.app.NtMain
import org.kotlintor.app.Shutdown
import org.kotlintor.app.SubsysMgr
import org.kotlintor.app.SubsystemList
import org.kotlintor.app.TorMain
import org.kotlintor.circuit.TraceProbesCircuit
import org.kotlintor.config.RiskyOptions
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.SharedRandomClient
import org.kotlintor.metrics.Metrics
import java.nio.file.Files

/**
 * Elevates app/main + remaining non-trunnel L1 D2 units.
 */
class AppMainElevationTest {
    @Test
    fun `main subsystem list shutdown tor_main`() {
        assertTrue(Main.subsystemNames().contains("relay"))
        assertEquals(SubsystemList.names().size, SubsysMgr.count())
        assertFalse(NtMain.serviceModeSupported())
        val c = TorConfig(dataDirectory = Files.createTempDirectory("ktor-app"))
        val d = TorMain.createDaemon(c)
        Shutdown.stop(d)
    }

    @Test
    fun `risky options metrics shared_random_client trace probes`() {
        val c = TorConfig(dataDirectory = Files.createTempDirectory("ktor-app2"))
        assertFalse(RiskyOptions.testingTorNetwork(c))
        Metrics.initialize()
        assertTrue(Metrics.isInitialized())
        Metrics.shutdown()
        assertFalse(Metrics.isInitialized())
        assertEquals(1, SharedRandomClient.protoVersion())
        TraceProbesCircuit.reset()
        TraceProbesCircuit.noteCreate()
        assertEquals(1L, TraceProbesCircuit.snapshot()["circ_create"])
    }
}
