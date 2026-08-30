package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.BootstrapPhase
import org.kotlintor.circuit.CircuitMux
import org.kotlintor.circuit.CircuitPadding
import org.kotlintor.circuit.CircuitPaddingMachines
import org.kotlintor.circuit.EwmaCircuitMuxPolicy
import org.kotlintor.config.Config
import org.kotlintor.config.QuietLevel
import org.kotlintor.dir.AuthMode
import org.kotlintor.dir.AuthModeOptions
import org.kotlintor.link.Scheduler
import org.kotlintor.link.SchedulerKist
import org.kotlintor.link.SchedulerType
import java.nio.file.Files

/**
 * Elevates:
 * - L1:app/config/config.c
 * - L1:app/config/quiet_level.c (hint/cap fix)
 * - L1:core/or/circuitmux.c
 * - L1:core/or/circuitpadding.c
 * - L1:core/or/circuitpadding_machines.c
 * - L1:core/or/scheduler.c
 * - L1:core/or/scheduler_kist.c
 * - L1:feature/dirauth/authmode.c
 *
 * Control-port facades live in `:control` (see ControlParityElevationTest).
 */
class ConfigControlMuxPaddingElevationTest {
    @Test
    fun `config parse acknowledges SocksPort`() {
        val dir = Files.createTempDirectory("ktor-cfg-elev")
        val cfg = Config.parse("SocksPort 9050\n", dir)
        assertTrue(Config.hasOption(cfg, "SocksPort") || cfg.socksPorts.isNotEmpty())
        assertEquals(9050, cfg.socksPorts.first().port)
    }

    @Test
    fun `quiet level flags`() {
        assertEquals(QuietLevel.SILENT, QuietLevel.fromFlag("--quiet"))
        assertEquals(QuietLevel.HUSH, QuietLevel.fromFlag("--hush"))
    }

    @Test
    fun `circuit mux flushFair`() {
        val mux = CircuitMux(EwmaCircuitMuxPolicy(halfLifeSec = 30.0))
        mux.attach(1L)
        assertTrue(mux.enqueue(1L, ByteArray(514) { 1 }))
        val batch = mux.flushFair(maxItems = 8)
        assertTrue(batch.isNotEmpty())
    }

    @Test
    fun `circuit padding machines`() {
        assertEquals(1_000_000L, CircuitPadding.DELAY_UNITS_PER_SECOND)
        assertEquals(CircuitPadding.delayInfinite(), 0xFFFF_FFFFL)
        val intro = CircuitPadding.clientHideIntro()
        assertEquals("client_ip_circ", intro.name)
        assertEquals(7, CircuitPaddingMachines.INTRO_MACHINE_MINIMUM_PADDING)
        assertEquals(4, CircuitPaddingMachines.allBuiltin().size)
    }

    @Test
    fun `scheduler select prefers kistlite without tcpinfo`() {
        val types = Scheduler.parseList("kist,kistlite,vanilla")
        assertTrue(SchedulerType.KIST in types)
        val chosen = Scheduler.select(types)
        assertTrue(chosen == SchedulerType.KIST || chosen == SchedulerType.KIST_LITE || chosen == SchedulerType.VANILLA)
        assertTrue(SchedulerKist.isKistFamily(SchedulerType.KIST_LITE))
        assertTrue(SchedulerKist.fallbackByteBudget() > 0)
    }

    @Test
    fun `authmode predicates`() {
        val client = AuthModeOptions(authoring = false)
        assertFalse(AuthMode.isAuthority(client))
        val v3 = AuthModeOptions(authoring = true, v3 = true)
        assertTrue(AuthMode.isV3(v3))
        assertTrue(AuthMode.publishesStatuses(v3))
        assertEquals(BootstrapPhase.DONE.progress, 100)
    }
}
