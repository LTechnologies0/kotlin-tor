package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Ed25519Keys

class OnionAddressV3Test {
    @Test
    fun `encode decode round trip`() {
        val kp = Ed25519Keys.generate()
        val addr = OnionAddressV3.encode(kp.publicKey)
        assertTrue(addr.endsWith(".onion"))
        assertEquals(56 + ".onion".length, addr.length)
        val pub = OnionAddressV3.decode(addr)
        assertTrue(pub.contentEquals(kp.publicKey))
    }
}
