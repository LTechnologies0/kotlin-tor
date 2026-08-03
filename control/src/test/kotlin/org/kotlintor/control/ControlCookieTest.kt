package org.kotlintor.control

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes
import org.kotlintor.util.toHex

class ControlCookieTest {
    @Test
    fun `server and client hashes are 32 bytes and distinct`() {
        val cookie = ByteArray(32) { 1 }
        val clientNonce = ByteArray(32) { 2 }
        val serverNonce = ByteArray(32) { 3 }
        val server = ControlCookie.serverHash(cookie, clientNonce, serverNonce)
        val client = ControlCookie.clientHash(cookie, clientNonce, serverNonce)
        assertEquals(32, server.size)
        assertEquals(32, client.size)
        assertFalse(server.contentEquals(client))
    }

    @Test
    fun `hmacChallenge alias is clientHash`() {
        val cookie = ByteArray(32) { 0x11 }
        val cn = ByteArray(16) { 0x22 }
        val sn = ByteArray(32) { 0x33 }
        assertArrayEquals(
            ControlCookie.clientHash(cookie, cn, sn),
            ControlCookie.hmacChallenge(cookie, cn, sn),
        )
    }

    @Test
    fun `deterministic vector round trip`() {
        // Fixed inputs — verify HMAC-SHA256 with the Tor string keys.
        val cookie = hexToBytes("00".repeat(32))
        val clientNonce = hexToBytes("11".repeat(32))
        val serverNonce = hexToBytes("22".repeat(32))
        val server = ControlCookie.serverHash(cookie, clientNonce, serverNonce)
        val client = ControlCookie.clientHash(cookie, clientNonce, serverNonce)
        // Recompute with javax.crypto for an independent check of key/msg layout.
        fun hmac(key: String, msg: ByteArray): ByteArray {
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(javax.crypto.spec.SecretKeySpec(key.toByteArray(), "HmacSHA256"))
            return mac.doFinal(msg)
        }
        val msg = cookie + clientNonce + serverNonce
        assertArrayEquals(
            hmac("Tor safe cookie authentication server-to-controller hash", msg),
            server,
        )
        assertArrayEquals(
            hmac("Tor safe cookie authentication controller-to-server hash", msg),
            client,
        )
    }
}
