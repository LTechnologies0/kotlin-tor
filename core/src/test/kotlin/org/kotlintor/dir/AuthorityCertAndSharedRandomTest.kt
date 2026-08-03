package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes
import org.kotlintor.util.toHex
import java.nio.file.Files

class AuthorityCertAndSharedRandomTest {
    @Test
    fun `authority cert generate parse verify roundtrip`() {
        val mat = AuthorityCert.generate(bits = 2048)
        val doc = mat.formatCertificate(address = "127.0.0.1", dirPort = 9030)
        assertTrue(doc.startsWith("dir-key-certificate-version 3"))
        assertTrue(doc.contains("dir-identity-key"))
        assertTrue(doc.contains("dir-signing-key"))
        assertTrue(doc.contains("BEGIN SIGNATURE"))
        val parsed = AuthorityCert.parse(doc)
        assertEquals(3, parsed.version)
        assertEquals(mat.identityFingerprint.toHex().uppercase(), parsed.fingerprintHex.replace(" ", ""))
        assertTrue(AuthorityCert.verify(parsed))
        val tmp = Files.createTempDirectory("ktor-authcert")
        AuthorityCert.persist(mat, tmp, doc)
        val loaded = AuthorityCert.loadMaterial(tmp)!!
        assertTrue(AuthorityCert.verify(AuthorityCert.parse(loaded.formatCertificate())))
    }

    @Test
    fun `shared random commit reveal srv deterministic`() {
        val idA = hexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        val idB = hexToBytes("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        val rnA = ByteArray(32) { 1 }
        val rnB = ByteArray(32) { 2 }
        val cA = SharedRandom.generateCommit(idA, timestampEpochSec = 1_700_000_000L, randomNumber = rnA)
        val cB = SharedRandom.generateCommit(idB, timestampEpochSec = 1_700_000_000L, randomNumber = rnB)
        assertTrue(SharedRandom.verifyRevealMatchesCommit(cA))
        assertTrue(cA.voteLine(SharedRandom.Phase.COMMIT).startsWith("shared-rand-commit 1 sha3-256"))
        val srv1 = SharedRandom.computeSrv(listOf(cA, cB))
        val srv2 = SharedRandom.computeSrv(listOf(cB, cA)) // order independent after sort
        assertTrue(srv1.value.contentEquals(srv2.value))
        assertEquals(2L, srv1.numReveals)
        assertTrue(srv1.toNsLine().startsWith("shared-rand-current-value 2 "))
        val next = SharedRandom.computeSrv(listOf(cA, cB), previous = srv1)
        assertTrue(!next.value.contentEquals(srv1.value))
    }
}
