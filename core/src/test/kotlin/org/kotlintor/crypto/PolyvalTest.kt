package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes

class PolyvalTest {
    @Test
    fun `RFC 8452 appendix A worked example`() {
        val h = hexToBytes("25629347589242761d31f826ba4b757b")
        val x1 = hexToBytes("4f4f95668c83dfb6401762bb2d01a262")
        val x2 = hexToBytes("d1a24ddd2721d006bbe45f20d3c9f362")
        val expect = hexToBytes("f7a3b47b846119fae5b7866cf5e5b77e")
        assertArrayEquals(expect, Polyval.polyval(h, listOf(x1, x2)))
    }
}
