package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.toHex
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

class ConsensusVerifierTest {
    private val tsFmt =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)

    @Test
    fun `fake consensus signature fails`() {
        val auth = AuthorityCert.generate(bits = 1024)
        val cert = AuthorityCert.parse(auth.formatCertificate())
        assertTrue(AuthorityCert.verify(cert))
        val body = liveConsensusBody()
        val fake = body +
            "directory-signature sha1 ${cert.fingerprintHex.lowercase()} " +
            cert.signingKeyDigest.toHex() + "\n" +
            "-----BEGIN SIGNATURE-----\nAA==\n-----END SIGNATURE-----\n"
        val consensus = ConsensusParser.parse(fake)
        val v = ConsensusVerifier.verify(
            consensus,
            listOf(cert),
            setOf(cert.fingerprintHex),
            nAuthorities = 1,
        )
        assertFalse(v.ok, v.reason)
        assertTrue(v.validCount == 0)
        assertFalse(NetworkStatus.networkstatusCheckConsensusSignature(consensus))
    }

    @Test
    fun `valid rsa sha1 consensus signature meets quorum of one`() {
        val auth = AuthorityCert.generate(bits = 1024)
        val cert = AuthorityCert.parse(auth.formatCertificate())
        val body = liveConsensusBody()
        val sig = DetachedSignatures.signSha1Rsa(
            body,
            identityFingerprintHex = cert.fingerprintHex,
            signingKeyDigestHex = cert.signingKeyDigest.toHex(),
            signingPrivateKey = auth.signing.private,
        )
        val attached = DetachedSignatures.attachToConsensus(body, listOf(sig))
        val consensus = ConsensusParser.parse(attached)
        val v = ConsensusVerifier.verify(
            consensus,
            listOf(cert),
            setOf(cert.fingerprintHex),
            nAuthorities = 1,
        )
        assertTrue(v.ok, v.reason)
        assertTrue(v.validCount >= 1)
    }

    @Test
    fun `one valid signature fails majority of three`() {
        val auth = AuthorityCert.generate(bits = 1024)
        val cert = AuthorityCert.parse(auth.formatCertificate())
        val body = liveConsensusBody()
        val sig = DetachedSignatures.signSha1Rsa(
            body,
            identityFingerprintHex = cert.fingerprintHex,
            signingKeyDigestHex = cert.signingKeyDigest.toHex(),
            signingPrivateKey = auth.signing.private,
        )
        val attached = DetachedSignatures.attachToConsensus(body, listOf(sig))
        val consensus = ConsensusParser.parse(attached)
        val known = setOf(cert.fingerprintHex, "aa".repeat(20), "bb".repeat(20))
        val v = ConsensusVerifier.verify(
            consensus,
            listOf(cert),
            known,
            nAuthorities = 3,
        )
        assertFalse(v.ok, v.reason)
        assertTrue(v.validCount == 1)
        assertTrue(v.required == 2)
    }

    private fun liveConsensusBody(): String {
        val now = Instant.now()
        val after = tsFmt.format(now.minusSeconds(60))
        val fresh = tsFmt.format(now.plusSeconds(3600))
        val until = tsFmt.format(now.plusSeconds(7200))
        return buildString {
            appendLine("network-status-version 3")
            appendLine("vote-status consensus")
            appendLine("consensus-method 32")
            appendLine("valid-after $after")
            appendLine("fresh-until $fresh")
            appendLine("valid-until $until")
            appendLine("known-flags Fast Guard Running Stable Valid")
            appendLine("directory-footer")
        }
    }
}
