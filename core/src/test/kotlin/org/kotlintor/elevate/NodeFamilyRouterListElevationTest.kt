package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.NodeFamily
import org.kotlintor.dir.RouterList
import org.kotlintor.dir.RouterStatus
import java.time.Instant

class NodeFamilyRouterListElevationTest {
    @Test
    fun `node family parse and intern`() {
        NodeFamily.clearCache()
        val a = NodeFamily.parse("\$" + "AA".repeat(20) + " NickB", selfFp = "BB".repeat(20))!!
        assertTrue(a.fingerprints.contains("AA".repeat(20)))
        assertTrue(a.fingerprints.contains("BB".repeat(20)))
        val b = NodeFamily.parse("\$" + "aa".repeat(20) + " \$" + "bb".repeat(20))!!
        // Same member set → same interned instance key behavior
        assertTrue(a.intersects(b))
    }

    @Test
    fun `router list lookup`() {
        val rs = RouterStatus(
            nickname = "GuardOne",
            identity = ByteArray(20) { 0xAB.toByte() },
            digest = ByteArray(20),
            publication = Instant.EPOCH,
            ip = "1.2.3.4",
            orPort = 9001,
            dirPort = 0,
            flags = setOf("Running", "Fast", "Guard"),
            version = null,
            proto = emptyMap(),
            bandwidth = 100,
        )
        val list = RouterList()
        list.add(rs)
        assertEquals(1, list.size())
        assertNotNull(list.byNickname("guardone"))
        assertNotNull(list.byFingerprint(rs.fingerprintHex))
        assertNotNull(list.lookup("\$" + rs.fingerprintHex))
        assertNotNull(list.lookup("GuardOne"))
    }
}
