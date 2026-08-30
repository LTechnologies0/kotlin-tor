package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CryptPath
import org.kotlintor.circuit.ExtendInfo
import org.kotlintor.config.TorConfig
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.dir.TorCert
import org.kotlintor.metrics.MetricsSys
import java.nio.file.Files

/**
 * Elevates:
 * - L1:feature/metrics/metrics_sys.c
 * - L1:feature/nodelist/torcert.c
 * - L1:core/or/crypt_path.c
 */
class MetricsTorCertCryptPathElevationTest {
    @Test
    fun `metrics_sys initialize shutdown`() {
        MetricsSys.shutdown()
        assertFalse(MetricsSys.isInitialized())
        assertEquals(0, MetricsSys.initialize())
        assertTrue(MetricsSys.isInitialized())
        assertEquals(0, MetricsSys.initialize()) // idempotent
        val cfg = TorConfig(dataDirectory = Files.createTempDirectory("ktor-met"))
        assertFalse(MetricsSys.enabled(cfg))
        MetricsSys.shutdown()
        assertFalse(MetricsSys.isInitialized())
        assertEquals(0L, MetricsSys.snapshot()["relay_cells"])
        assertEquals("", MetricsSys.exportPrometheus())
    }

    @Test
    fun `torcert create parse checksig eq`() {
        val kp = Ed25519Keys.generate()
        val certified = ByteArray(32) { 2 }
        val cert = TorCert.createEd25519(
            certType = TorCert.TYPE_SIGNING_V_TLS_CERT,
            certifiedKey = certified,
            expirationHours = 1000,
            signingKeySeed = kp.privateKey,
            signedWithEd25519 = kp.publicKey,
        )
        assertTrue(TorCert.looksValid(cert))
        val parsed = TorCert.parse(cert)
        assertNotNull(parsed)
        assertEquals(0, TorCert.checksig(parsed!!, kp.publicKey))
        assertEquals("validated", TorCert.describeSignatureStatus(parsed))
        assertTrue(TorCert.eq(cert, parsed.raw))
        assertNull(TorCert.parse(byteArrayOf(1, 2, 3)))
    }

    @Test
    fun `crypt_path circular list and next non-open`() {
        val path = CryptPath.Path()
        assertEquals(0, path.nHops())
        val a = path.appendHop(
            ExtendInfo(identityDigest = ByteArray(20) { 1 }, orPorts = listOf(ExtendInfo.OrPort("1.1.1.1", 9001))),
        )
        val b = path.appendHop(
            ExtendInfo(identityDigest = ByteArray(20) { 2 }, orPorts = listOf(ExtendInfo.OrPort("2.2.2.2", 9001))),
        )
        assertEquals(2, path.nHops())
        assertEquals(a, path.nextNonOpenHop())
        a.state = CryptPath.State.OPEN
        // OPEN without crypto fails assertLayerOk — attach a stub by leaving crypto null and
        // only testing nextNonOpen before assertOk on open-without-crypto.
        assertEquals(b, path.nextNonOpenHop())
        b.state = CryptPath.State.OPEN
        assertNull(path.nextNonOpenHop())
        // restore closed for assertOk without crypto
        a.state = CryptPath.State.CLOSED
        b.state = CryptPath.State.CLOSED
        path.assertOk()
    }
}
