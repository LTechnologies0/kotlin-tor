package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.SecureRandomSource

class HsClientAuthTest {
    @Test
    fun `generate auth-client line`() {
        val entry = HsClientAuth.AuthClientEntry(
            clientId = SecureRandomSource.nextBytes(8),
            iv = SecureRandomSource.nextBytes(16),
            encryptedCookie = SecureRandomSource.nextBytes(16),
        )
        val line = HsClientAuth.authClientLine(entry)
        assertTrue(line.startsWith("auth-client "))
        assertTrue(line.split(' ').size >= 4)
    }
}
