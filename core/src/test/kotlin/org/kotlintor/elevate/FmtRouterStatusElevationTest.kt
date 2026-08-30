package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.dir.FmtRouterStatus
import org.kotlintor.dir.RouterStatus
import java.time.Instant

/**
 * Elevates `L1:feature/nodelist/fmt_routerstatus.c` D2→D3.
 *
 * Evidence: routerstatus_format_entry formats CONTROL/VOTE/MICRODESC + Measured /
 * GuardFraction / id ed25519 vs fmt_routerstatus.c.
 */
class FmtRouterStatusElevationTest {
    private fun sample(): RouterStatus = RouterStatus(
        nickname = "TestRelay",
        identity = ByteArray(20) { it.toByte() },
        digest = ByteArray(20) { (it + 1).toByte() },
        publication = Instant.parse("2024-01-02T03:04:05Z"),
        ip = "198.51.100.1",
        orPort = 9001,
        dirPort = 9030,
        flags = setOf("Fast", "Guard", "Running", "Stable", "Valid", "V2Dir"),
        version = "Tor 0.4.8.0",
        proto = mapOf("Link" to "1-5", "Relay" to "1-6"),
        bandwidth = 1000,
        ed25519Identity = ByteArray(32) { (it + 3).toByte() },
    )

    @Test
    fun `control port and microdesc`() {
        val rs = sample()
        val text = FmtRouterStatus.formatEntry(rs, FmtRouterStatus.Format.CONTROL_PORT)
        assertTrue(text.startsWith("r TestRelay "))
        assertTrue(text.contains("\ns "))
        assertTrue(text.contains(" Fast"))
        assertTrue(text.contains("\nv Tor 0.4.8.0\n"))
        assertTrue(text.contains("w Bandwidth=1000\n"))
        val micro = FmtRouterStatus.formatEntry(rs, FmtRouterStatus.Format.V3_CONSENSUS_MICRODESC)
        assertFalse(micro.contains("\ns "))
        assertFalse(micro.contains(FmtRouterStatus.digestToBase64(rs.digest)))
    }

    @Test
    fun `vote measured guardfraction id and stats`() {
        val rs = sample()
        val vote = FmtRouterStatus.VoteExtras(
            measuredBwKb = 2500,
            guardFractionPercent = 42,
            ed25519Id = rs.ed25519Identity,
            exitPolicySummary = "accept 80,443",
            statsWfu = 0.123456,
            statsTk = 99L,
            statsMtbf = 3600.0,
        )
        val text = FmtRouterStatus.formatEntry(rs, FmtRouterStatus.Format.V3_VOTE, vote = vote)
        assertTrue(text.contains(" Measured=2500"))
        assertTrue(text.contains(" GuardFraction=42"))
        assertTrue(text.contains("p accept 80,443\n"))
        assertTrue(text.contains("id ed25519 "))
        assertFalse(text.contains("id ed25519 none"))
        assertTrue(text.contains("stats wfu=0.123456 tk=99 mtbf=3600\n"))
        val auth = FmtRouterStatus.formatEntry(
            rs.copy(flags = rs.flags + "Authority"),
            FmtRouterStatus.Format.V3_VOTE,
            vote = vote.copy(isAuthority = true),
        )
        assertTrue(auth.contains(" MeasuredButAuthority=2500"))
    }
}
