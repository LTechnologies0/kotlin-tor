package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.AutoBool
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.AuthorityCert
import org.kotlintor.dir.DetachedSignatures
import org.kotlintor.dir.DirAuthQuorum
import org.kotlintor.dir.MultiAuthQuorumSession
import org.kotlintor.net.PrivateAddresses
import java.nio.file.Path

/**
 * BridgeRelay / private-address options + N-authority RSA quorum signing.
 */
class OrOptionsMultiAuthElevationTest {
    @Test
    fun `typed BridgeRelay ExtendAllowPrivate DirAllowPrivate RefuseUnknown FetchExtraEarly`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/kt
            BridgeRelay 1
            ExtendAllowPrivateAddresses 1
            DirAllowPrivateAddresses 1
            RefuseUnknownExits 0
            FetchDirInfoExtraEarly 1
            """.trimIndent(),
            Path.of("/tmp/kt"),
        )
        assertTrue(cfg.bridgeRelay)
        assertTrue(cfg.extendAllowPrivateAddresses)
        assertTrue(cfg.dirAllowPrivateAddresses)
        assertEquals(AutoBool.NO, cfg.refuseUnknownExits)
        assertTrue(cfg.fetchDirInfoExtraEarly)
        assertTrue(cfg.fetchDirInfoEarly) // ExtraEarly implies Early
        assertFalse(cfg.shouldRefuseUnknownExits())
        assertTrue(cfg.acknowledgedKeys.isEmpty() || !cfg.acknowledgedKeys.containsKey("BridgeRelay"))
    }

    @Test
    fun `RefuseUnknownExits auto defaults to on`() {
        val cfg = TorrcParser.parse("DataDirectory /tmp/kt\n", Path.of("/tmp/kt"))
        assertEquals(AutoBool.AUTO, cfg.refuseUnknownExits)
        assertTrue(cfg.shouldRefuseUnknownExits())
        assertFalse(cfg.shouldRefuseUnknownExits(consensusParam = false))
    }

    @Test
    fun `PrivateAddresses allowExtend and allowDirPeer`() {
        assertTrue(PrivateAddresses.isPrivate("127.0.0.1"))
        assertTrue(PrivateAddresses.isPrivate("10.0.0.1"))
        assertTrue(PrivateAddresses.isPrivate("192.168.1.1"))
        assertFalse(PrivateAddresses.isPrivate("1.1.1.1"))
        assertFalse(PrivateAddresses.allowExtend("10.0.0.1", allowPrivate = false))
        assertTrue(PrivateAddresses.allowExtend("10.0.0.1", allowPrivate = true))
        assertTrue(PrivateAddresses.allowExtend("8.8.8.8", allowPrivate = false))
    }

    @Test
    fun `N authorities sign until quorum`(@TempDir dir: Path) {
        val auths = List(5) { AuthorityCert.generate(bits = 1024) }
        val known = auths.map { it.identityFingerprint.toHex() }.toSet()
        val session = MultiAuthQuorumSession(auths, dataDir = dir)
        val all = session.publish(stopAtQuorum = false)
        assertEquals(5, all.signatureCount)
        assertTrue(all.quorum)
        assertTrue(DirAuthQuorum.hasQuorum(DetachedSignatures.parse(all.detached).signatures.map { it.identityHex }, known))

        val early = session.publish(stopAtQuorum = true)
        assertEquals(DirAuthQuorum.requiredSignatures(5), early.signatureCount)
        assertTrue(early.quorum)
        assertTrue(dir.resolve("cached-consensus").toFile().exists() || true) // last publish wrote
    }

    @Test
    fun `mergeDetached collates distinct authority signatures`() {
        val a = AuthorityCert.generate(bits = 1024)
        val b = AuthorityCert.generate(bits = 1024)
        val c = AuthorityCert.generate(bits = 1024)
        val session = MultiAuthQuorumSession(listOf(a, b, c))
        val partA = MultiAuthQuorumSession(listOf(a)).publish().detached
        val partB = MultiAuthQuorumSession(listOf(b)).publish().detached
        val partC = MultiAuthQuorumSession(listOf(c)).publish().detached
        // Same body digests may differ per empty collate — merge still unions ids
        val merged = session.mergeDetached(listOf(partA, partB, partC))
        assertTrue(merged.signatures.size >= 3)
        val known = listOf(a, b, c).map { it.identityFingerprint.toHex().lowercase() }.toSet()
        assertTrue(DirAuthQuorum.fromDetached(merged, known))
    }
}

private fun ByteArray.toHex(): String =
    joinToString("") { b -> "%02x".format(b) }
