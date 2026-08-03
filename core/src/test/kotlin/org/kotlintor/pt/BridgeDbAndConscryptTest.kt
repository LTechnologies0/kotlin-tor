package org.kotlintor.pt

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.link.TorSsl

class BridgeDbAndConscryptTest {
    @Test
    fun `extract bridge lines from moat-like json`() {
        val json = """{"settings":[{"bridges":{"type":"obfs4","source":"bridgedb",
            "bridge_strings":["obfs4 1.2.3.4:443 AABB cert=xx iat-mode=0",
            "snowflake 192.0.2.1:80"]}}]}"""
        val lines = BridgeDbClient().extractBridgeLines(json)
        assertEquals(2, lines.size)
        assertTrue(lines[0].startsWith("obfs4 "))
        assertTrue(lines[1].startsWith("snowflake "))
    }

    @Test
    fun `conscrypt installs for TLS exporter`() {
        assertTrue(TorSsl.installConscrypt())
        assertTrue(TorSsl.usingConscrypt)
        // Force socket factory init
        TorSsl.socketFactory
    }
}
