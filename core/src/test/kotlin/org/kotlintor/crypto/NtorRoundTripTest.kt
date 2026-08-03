package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NtorRoundTripTest {
    @Test
    fun `client and server derive identical circuit keys`() {
        val identity = ByteArray(20) { it.toByte() }
        val onion = Curve25519.generateKeyPair()
        val client = Ntor.clientHandshake(identity, onion.publicKey)
        val server = NtorServer.respond(identity, onion.privateKey, onion.publicKey, client.handshake)
        val finished = Ntor.clientFinish(client, identity, onion.publicKey, server.handshake)
        assertTrue(finished.forwardKey.contentEquals(server.result.forwardKey))
        assertTrue(finished.backwardKey.contentEquals(server.result.backwardKey))
        assertTrue(finished.forwardDigest.contentEquals(server.result.forwardDigest))
        assertTrue(finished.backwardDigest.contentEquals(server.result.backwardDigest))
    }

    @Test
    fun `hkdf empty ikm matches tor proposal vector prefix`() {
        // From prop 216: INPUT "" first 20 bytes of 100-byte expand
        val keySeed = Digests.hmacSha256(
            "ntor-curve25519-sha256-1:key_extract".toByteArray(),
            ByteArray(0),
        )
        val out = Hkdf.expand(keySeed, "ntor-curve25519-sha256-1:key_expand".toByteArray(), 100)
        val expectPrefix = "d3490ed48b12a48f9547861583573fe3f19aafe3"
        assertTrue(out.copyOf(20).joinToString("") { "%02x".format(it) } == expectPrefix)
    }
}
