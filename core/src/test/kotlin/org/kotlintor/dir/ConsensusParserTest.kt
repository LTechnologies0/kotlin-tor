package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ConsensusParserTest {
    @Test
    fun `parse minimal consensus fragment`() {
        val text = """
            network-status-version 3
            vote-status consensus
            consensus-method 32
            valid-after 2026-08-01 00:00:00
            fresh-until 2026-08-01 01:00:00
            valid-until 2026-08-01 03:00:00
            r Unnamed AAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-08-01 00:00:00 1.2.3.4 9001 0
            s Fast Guard Running Stable Valid
            w Bandwidth=1000
            directory-footer
        """.trimIndent()
        // identity/digest need valid base64 of 20 bytes — use real encoding
        val id = ByteArray(20) { 0x11 }
        val dig = ByteArray(20) { 0x22 }
        val idB64 = java.util.Base64.getEncoder().withoutPadding().encodeToString(id)
        val digB64 = java.util.Base64.getEncoder().withoutPadding().encodeToString(dig)
        val fixed = text.replace(
            "r Unnamed AAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-08-01 00:00:00 1.2.3.4 9001 0",
            "r Unnamed $idB64 $digB64 2026-08-01 00:00:00 1.2.3.4 9001 0",
        )
        val c = ConsensusParser.parse(fixed)
        assertEquals(1, c.relays.size)
        assertTrue(c.relays[0].isGuard)
        assertEquals(1000, c.relays[0].bandwidth)
        assertEquals("1.2.3.4", c.relays[0].ip)
    }
}
