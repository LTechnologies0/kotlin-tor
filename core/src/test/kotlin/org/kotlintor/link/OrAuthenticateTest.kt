package org.kotlintor.link

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519Keys

class OrAuthenticateTest {
    @Test
    fun `AUTH0003 build parse verify roundtrip`() {
        val kp = Ed25519Keys.generate()
        val cid = Digests.sha256("cid".toByteArray())
        val sid = Digests.sha256("sid".toByteArray())
        val cidEd = kp.publicKey
        val sidEd = Ed25519Keys.generate().publicKey
        val slog = Digests.sha256("slog".toByteArray())
        val clog = Digests.sha256("clog".toByteArray())
        val scert = Digests.sha256("scert".toByteArray())
        val tls = Digests.sha256("tls".toByteArray())
        val body = OrAuthenticate.build(
            cidRsaSha256 = cid,
            sidRsaSha256 = sid,
            cidEd = cidEd,
            sidEd = sidEd,
            slog = slog,
            clog = clog,
            scertSha256 = scert,
            tlsSecrets = tls,
            linkEdPrivate = kp.privateKey,
        )
        val cell = OrAuthenticate.toCell(body)
        val parsed = OrAuthenticate.parse(cell.payload)
        assertTrue(OrAuthenticate.verify(parsed, cidEd))
        assertEquals(32, parsed.cid.size)
        assertEquals(64, parsed.sig.size)
    }
}
