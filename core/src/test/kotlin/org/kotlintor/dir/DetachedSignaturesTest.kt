package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Ed25519Keys

class DetachedSignaturesTest {
    @Test
    fun `sign verify and parse detached`() {
        val kp = Ed25519Keys.generate()
        val body = BandwidthVote.formatMinimalVote("R", "ID", 10)
        val sig = DetachedSignatures.signEd25519(body, "aabb", kp.privateKey, kp.publicKey)
        assertTrue(DetachedSignatures.verifyEd25519(body, kp.publicKey, sig.signature))
        val detached = DetachedSignatures.formatDetached(
            body,
            "2020-01-01 00:00:00",
            "2020-01-01 01:00:00",
            "2020-01-01 02:00:00",
            listOf(sig),
        )
        val parsed = DetachedSignatures.parse(detached)
        assertEquals("2020-01-01 00:00:00", parsed.validAfter)
        assertTrue(parsed.digests.containsKey("ns"))
        assertEquals(1, parsed.signatures.size)
        assertEquals("ed25519", parsed.signatures[0].algorithm)
        val attached = DetachedSignatures.attachToConsensus(body, listOf(sig))
        assertTrue(attached.contains("directory-signature"))
    }
}
