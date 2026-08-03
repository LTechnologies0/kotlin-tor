package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.SecureRandomSource

class HsClientAuthTest {
    @Test
    fun `generate auth-client line`() {
        val cred = HsClientAuth.generate("alice")
        val enc = SecureRandomSource.nextBytes(16)
        val line = HsClientAuth.authClientLine(cred, enc)
        assertTrue(line.startsWith("auth-client "))
        assertTrue(line.split(' ').size >= 4)
    }
}
