package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes

class CreateFastTest {
    @Test
    fun `client server round trip`() {
        val (st, x) = CreateFast.clientBegin()
        val (hs, serverKeys) = CreateFast.serverRespond(x)
        val clientKeys = CreateFast.clientFinish(st, hs)
        assertArrayEquals(serverKeys.kh, clientKeys.kh)
        assertArrayEquals(serverKeys.forwardKey, clientKeys.forwardKey)
        assertArrayEquals(serverKeys.backwardKey, clientKeys.backwardKey)
    }

    @Test
    fun `KDF-TOR known vector from zero seed`() {
        // SHA1(20×0 ‖ 0x00) first block
        val seed = ByteArray(40)
        val out = CreateFast.kdfTor(seed, 20)
        assertEquals(20, out.size)
        assertArrayEquals(Digests.sha1(seed + byteArrayOf(0)), out)
    }

    @Test
    fun `derive layout lengths`() {
        val r = CreateFast.derive(hexToBytes("11".repeat(40)))
        assertEquals(20, r.kh.size)
        assertEquals(20, r.forwardDigest.size)
        assertEquals(16, r.forwardKey.size)
        assertEquals(16, r.backwardKey.size)
    }
}
