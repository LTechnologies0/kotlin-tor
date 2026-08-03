package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.ExtendInfo
import org.kotlintor.config.ListenSpec
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.DirAuthOptions
import org.kotlintor.dir.DirAuthPeriodic
import org.kotlintor.dir.DirAuthSys
import org.kotlintor.dir.DirClientModes
import org.kotlintor.dir.DirList
import org.kotlintor.dir.DirParseCommon
import org.kotlintor.dir.DirSigning
import org.kotlintor.dir.Keypin
import org.kotlintor.dir.PolicyParse
import org.kotlintor.dir.TorCert
import org.kotlintor.dir.UnparseableDump
import org.kotlintor.util.hexToBytes
import java.nio.file.Files
import java.nio.file.Path

/**
 * Elevates D1 to D2 for dirauth keypin, dirparse helpers, dirlist, torcert, extendinfo.
 */
class DirAuthDirParseElevationTest {
    private val dataDir: Path = Path.of("/tmp/ktor-elevate-dirauth")

    @Test
    fun `keypin journal persist and verify`() {
        val j = Keypin.Journal()
        val rsa = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        val ed = ByteArray(32) { 3 }
        assertEquals(Keypin.Result.ADDED, j.checkAndAdd(rsa, ed))
        assertTrue(j.verifyAll())
        val path = dataDir.resolve("keypin.txt")
        Files.createDirectories(dataDir)
        j.saveTo(path)
        val j2 = Keypin.Journal()
        assertTrue(j2.loadFrom(path))
        assertEquals(1, j2.size())
        assertEquals(Keypin.Result.OK, j2.check(rsa, ed))
    }

    @Test
    fun `dirauth options periodics and dirparse edges`() {
        val c = TorConfig(
            dataDirectory = dataDir,
            authoritativeDirectory = true,
            v3AuthoritativeDirectory = true,
            orPort = ListenSpec("127.0.0.1", 9001),
        )
        val opts = DirAuthOptions.fromTorConfig(c)
        assertTrue(opts.enabled())
        assertTrue(opts.validate().isEmpty())
        DirAuthSys.init(c)
        assertTrue(DirAuthSys.isStarted())
        DirAuthSys.noteVoteAct()
        assertEquals(1, DirAuthSys.voteActCount())
        assertTrue(DirAuthPeriodic.scheduleHints(c).containsKey("vote_interval_sec"))
        assertTrue(DirClientModes.directoryFetchesV3(c))
        assertFalse(DirClientModes.directoryFetchesV2(c))

        val doc = "network-status-version 3\nr A AA\nr B BB\n"
        assertEquals(2, DirParseCommon.keywordAll(doc, "r").size)
        assertTrue(DirParseCommon.hasKeyword(doc, "network-status-version"))
        assertTrue(PolicyParse.isWellFormed("reject *:*"))
        assertFalse(PolicyParse.isWellFormed("nope"))
        UnparseableDump.note("x", "bad")
        assertTrue("x" in UnparseableDump.tags())
        val signed = "body\n-----BEGIN SIGNATURE-----\nAbCd\n-----END SIGNATURE-----\n"
        assertTrue(DirSigning.stripSignatures(signed).startsWith("body"))
        assertEquals(0x08, TorCert.TYPE_BLINDED_ID_V_SIGNING)
    }

    @Test
    fun `dirlist remove and extendinfo describe`() {
        val list = DirList.withDefaults()
        val n = list.size()
        assertTrue(n >= 8)
        val first = list.trusted().first()
        if (first.v3IdentityHex != null) {
            list.removeByIdentity(first.v3IdentityHex!!)
            assertEquals(n - 1, list.size())
        }
        val id = hexToBytes("cccccccccccccccccccccccccccccccccccccccc")
        val ei = ExtendInfo(
            nickname = "N",
            identityDigest = id,
            orPorts = listOf(ExtendInfo.OrPort("1.2.3.4", 9001)),
            curve25519OnionKey = ByteArray(32),
        )
        assertTrue(ExtendInfo.describe(ei).contains("N/"))
        assertTrue(ExtendInfo.describe(ei).contains("1.2.3.4:9001"))
    }
}
