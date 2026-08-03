package org.kotlintor.crypto

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ControlS2kTest {
    @Test
    fun `hash and verify round trip`() {
        val hashed = ControlS2k.hashPassword("correct horse battery staple")
        assertTrue(hashed.startsWith("16:"))
        assertTrue(ControlS2k.verify("correct horse battery staple", hashed))
        assertFalse(ControlS2k.verify("wrong password", hashed))
    }
}
