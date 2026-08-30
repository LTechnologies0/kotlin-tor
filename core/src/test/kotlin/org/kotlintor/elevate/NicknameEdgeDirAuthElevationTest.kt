package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.cell.Reasons
import org.kotlintor.circuit.EdgeConnectionTable
import org.kotlintor.circuit.EdgeStreamState
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.Describe
import org.kotlintor.dir.Nickname
import org.kotlintor.dir.NodeSelect
import org.kotlintor.dir.RouterStatus
import java.nio.file.Path
import java.time.Instant

class NicknameEdgeDirAuthElevationTest {
    @Test
    fun `nickname validators`() {
        assertTrue(Nickname.isLegalNickname("KotlinTor"))
        assertFalse(Nickname.isLegalNickname(""))
        assertFalse(Nickname.isLegalNickname("this-name-is-way-too-long-for-tor"))
        assertTrue(Nickname.isLegalHexdigest("\$" + "A".repeat(40)))
        assertTrue(Nickname.isLegalNicknameOrHexdigest("\$" + "ab".repeat(20) + "~Nice"))
        assertEquals("A".repeat(40), Nickname.parseHexdigest("\$" + "a".repeat(40) + "=Nick"))
    }

    @Test
    fun `describe router`() {
        val d = Describe.node("Guard1", "AA".repeat(20), "1.2.3.4", 9001)
        assertTrue(d.startsWith("\$"))
        assertTrue(d.contains("~Guard1"))
        // C Tor format_node_description: " at <addr>" without ORPort
        assertTrue(d.contains(" at 1.2.3.4"))
        assertFalse(d.contains(":9001"))
    }

    @Test
    fun `node select by bandwidth`() {
        fun rs(nick: String, bw: Long, fp: String) = RouterStatus(
            nickname = nick,
            identity = ByteArray(20) { fp[it % fp.length].code.toByte() },
            digest = ByteArray(20),
            publication = Instant.EPOCH,
            ip = "127.0.0.1",
            orPort = 9001,
            dirPort = 0,
            flags = setOf("Running", "Fast", "Guard"),
            version = null,
            proto = emptyMap(),
            bandwidth = bw,
        )
        val pool = listOf(rs("A", 1, "aaaa"), rs("B", 1000, "bbbb"), rs("C", 1, "cccc"))
        val picks = (1..40).mapNotNull { NodeSelect.byBandwidth(pool)?.nickname }
        assertTrue(picks.count { it == "B" } > picks.count { it == "A" })
        val three = NodeSelect.pickDistinct(pool, 3)
        assertEquals(3, three.size)
        assertEquals(3, three.map { it.fingerprintHex }.toSet().size)
    }

    @Test
    fun `edge connection table`() {
        val t = EdgeConnectionTable()
        val s = t.open(7, 1, "example.com:443", isExit = false)
        assertEquals(EdgeStreamState.CONNECTING, s.state)
        t.markOpen(7, 1)
        t.noteBytes(7, 1, read = 10, written = 20)
        assertEquals(1, t.countOpen())
        t.markEnd(7, 1, Reasons.STREAM_DONE)
        assertEquals(0, t.countOpen())
        assertEquals(Reasons.STREAM_DONE, t.get(7, 1)!!.endReason)
    }

    @Test
    fun `authoritative dir torrc`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/ktor-auth
            AuthoritativeDirectory 1
            V3AuthoritativeDirectory 1
            TestingTorNetwork 1
            Nickname GoodNick
            """.trimIndent(),
            Path.of("/tmp/ktor-auth"),
        )
        assertTrue(cfg.authoritativeDirectory)
        assertTrue(cfg.v3AuthoritativeDirectory)
        assertTrue(cfg.testingTorNetwork)
        assertEquals("GoodNick", cfg.nickname)
        assertNotNull(cfg)
    }
}
