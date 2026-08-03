package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes
import org.kotlintor.util.toHex

class CryptoTest {
    @Test
    fun `sha256 empty vector`() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            Digests.sha256(ByteArray(0)).toHex(),
        )
    }

    @Test
    fun `aes ctr round trip`() {
        val key = hexToBytes("000102030405060708090a0b0c0d0e0f")
        val cipher = AesCtr(key)
        val plain = "kotlin-tor-aes-test".toByteArray()
        val enc = cipher.process(plain)
        val cipher2 = AesCtr(key)
        val dec = cipher2.process(enc)
        assertTrue(plain.contentEquals(dec))
    }

    @Test
    fun `x25519 agreement`() {
        val a = Curve25519.generateKeyPair()
        val b = Curve25519.generateKeyPair()
        val ab = Curve25519.sharedSecret(a.privateKey, b.publicKey)
        val ba = Curve25519.sharedSecret(b.privateKey, a.publicKey)
        assertTrue(ab.contentEquals(ba))
    }

    @Test
    fun `ed25519 sign verify`() {
        val kp = Ed25519Keys.generate()
        val msg = "kotlin-tor".toByteArray()
        val sig = Ed25519Keys.sign(kp.privateKey, msg)
        assertTrue(Ed25519Keys.verify(kp.publicKey, msg, sig))
    }

    @Test
    fun `hkdf length`() {
        val out = Hkdf.hkdf("ikm".toByteArray(), "salt".toByteArray(), "info".toByteArray(), 42)
        assertEquals(42, out.size)
    }

    @Test
    fun `ntor handshake size`() {
        val id = ByteArray(20) { 1 }
        val onion = Curve25519.generateKeyPair().publicKey
        val state = Ntor.clientHandshake(id, onion)
        assertEquals(20 + 32 + 32, state.handshake.size)
    }

    @Test
    fun `running sha1 preview does not mutate`() {
        val r = RunningSha1()
        r.update("abc".toByteArray())
        val p1 = r.preview("def".toByteArray())
        val p2 = r.preview("def".toByteArray())
        assertTrue(p1.contentEquals(p2))
        val peek = r.peek()
        assertEquals(20, peek.size)
    }
}
