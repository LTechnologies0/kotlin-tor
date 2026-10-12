package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MicrodescExitPolicyTest {
    @Test
    fun `accept port list`() {
        assertTrue(MicrodescExitPolicy.allowsPort("accept 80,443", 443))
        assertFalse(MicrodescExitPolicy.allowsPort("accept 80,443", 22))
        assertTrue(MicrodescExitPolicy.allowsPort("accept 1-65535", 9050))
        assertTrue(MicrodescExitPolicy.allowsPort("reject 25", 443))
        assertFalse(MicrodescExitPolicy.allowsPort("reject 25", 25))
        assertFalse(MicrodescExitPolicy.allowsPort(null, 80))
        assertEquals("accept 80", MicrodescExitPolicy.parseSummary("p accept 80"))
    }
}
