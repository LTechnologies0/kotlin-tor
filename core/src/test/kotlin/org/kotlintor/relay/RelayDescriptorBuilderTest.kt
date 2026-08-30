package org.kotlintor.relay

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Digests
import org.kotlintor.dir.SigCommon
import java.time.Instant

class RelayDescriptorBuilderTest {
    @Test
    fun `digestSha1Hex matches router_get_router_hash region`() {
        val doc = RelayDescriptorBuilder.build(
            RelayDescriptorBuilder.Input(
                nickname = "TestRelay",
                address = "127.0.0.1",
                orPort = 9001,
                dirPort = 0,
                identityFingerprintHex = "AA".repeat(20),
                ntorOnionKey = ByteArray(32) { 1 },
                ed25519Identity = ByteArray(32) { 2 },
            ),
            published = Instant.parse("2020-01-01T00:00:00Z"),
        )
        assertTrue(doc.contains("contact "))
        assertTrue(doc.indexOf("contact ") < doc.indexOf("router-signature"))
        assertTrue(!doc.contains("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")) // no invented RSA stub

        val expected = SigCommon.getHashImpl(
            doc,
            "router ",
            "\nrouter-signature",
            '\n',
            SigCommon.DigestAlg.SHA1,
        )!!
        val digHex = RelayDescriptorBuilder.digestSha1Hex(doc)
        assertEquals(expected.joinToString("") { "%02x".format(it) }, digHex)
        // Signature object after the keyword line must not change the digest.
        val withPem = doc + "-----BEGIN SIGNATURE-----\nAAAA\n-----END SIGNATURE-----\n"
        assertEquals(digHex, RelayDescriptorBuilder.digestSha1Hex(withPem))
        val wholeWithPem = Digests.sha1(withPem.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02x".format(it) }
        assertTrue(wholeWithPem != digHex)
    }
}
