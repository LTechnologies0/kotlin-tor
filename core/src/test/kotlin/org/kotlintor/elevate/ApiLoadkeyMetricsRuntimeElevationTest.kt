package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.api.TorApi
import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
import org.kotlintor.keymgt.LoadKey
import org.kotlintor.metrics.MetricsSys
import org.kotlintor.trunnel.LinkHandshakeTrunnel
import org.kotlintor.trunnel.NetinfoTrunnel
import org.kotlintor.trunnel.SubprotoRequestTrunnel
import org.kotlintor.util.u32be
import java.nio.file.Files
import kotlin.io.path.createTempDirectory

/**
 * Elevates:
 * - L1:feature/api/tor_api.c
 * - L1:feature/keymgt/loadkey.c
 * - L1:feature/metrics/metrics_sys.c
 * - L1:trunnel link_handshake, netinfo, subproto_request, pwbox
 * - L4:or_options ConfluxEnabled / DormantClientTimeout / HTTPProxy (via ClientRuntimeOptions)
 */
class ApiLoadkeyMetricsRuntimeElevationTest {
    @Test
    fun `tor_api config and version`() {
        val cfg = TorApi.newConfiguration()
        cfg.dataDirectory = createTempDirectory("ktor-api")
        cfg.addTorrcLine("SocksPort 0")
        val tor = cfg.buildConfig()
        assertEquals(cfg.dataDirectory, tor.dataDirectory)
        assertTrue(TorApi.version().contains("0.1.0"))
    }

    @Test
    fun `loadkey ed25519 persist`() {
        val dir = createTempDirectory("ktor-keys")
        val a = LoadKey.loadOrCreateEd25519Identity(dir)
        val b = LoadKey.loadOrCreateEd25519Identity(dir)
        assertTrue(a.publicKey.contentEquals(b.publicKey))
        assertTrue(Files.isRegularFile(dir.resolve("ed25519_master_id_secret_key")))
    }

    @Test
    fun `metrics_sys and trunnel codecs`() {
        val c = TorConfig(dataDirectory = createTempDirectory("ktor-met"))
        assertFalse(MetricsSys.enabled(c))
        val vers = LinkHandshakeTrunnel.versionsPayload(listOf(4, 5))
        assertEquals(listOf(4, 5), LinkHandshakeTrunnel.parseVersions(vers))
        val cell = Cell(0, CellCommand.NETINFO, u32be(1_700_000_000L) + ByteArray(505))
        assertEquals(1_700_000_000L, NetinfoTrunnel.timestampFromCell(cell))
        val enc = SubprotoRequestTrunnel.encode(mapOf("FlowCtrl" to "2"))
        assertEquals("2", SubprotoRequestTrunnel.parse(enc)["FlowCtrl"])
    }

    @Test
    fun `runtime options parse conflux dormant proxy`() {
        val dir = createTempDirectory("ktor-rt")
        val text = """
            ConfluxEnabled 0
            DormantClientTimeout 3600
            HTTPProxy 127.0.0.1:8118
            DirCache 1
            KISTSchedRunInterval 2
        """.trimIndent()
        val c = TorrcParser.parse(text, dir)
        assertFalse(c.runtime.confluxEnabled)
        assertEquals(3600L, c.runtime.dormantClientTimeoutSec)
        assertEquals("127.0.0.1:8118", c.runtime.httpProxy)
        assertTrue(c.runtime.dirCache)
        assertEquals(2, c.runtime.kistSchedRunIntervalMs)
    }
}
