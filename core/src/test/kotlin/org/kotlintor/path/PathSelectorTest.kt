package org.kotlintor.path

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.RouterStatus
import java.nio.file.Path

class PathSelectorTest {
    @Test
    fun `samples up to three sticky guards`(@TempDir dir: Path) {
        val config = TorConfig(dataDirectory = dir)
        val state = dir.resolve("guards")
        val sel = PathSelector(config, state)
        val relays = (1..10).map { i ->
            fakeGuard("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".replaceRange(0, 2, "%02X".format(i)), i * 10L)
        } + listOf(fakeExit())

        // Multiple selects should fill sample ≤ 3 and persist.
        repeat(5) { sel.select(relays) }
        assertTrue(sel.sampledGuards().size in 1..PathSelector.SAMPLE_SIZE)
        assertTrue(state.toFile().exists())

        val sel2 = PathSelector(config, state)
        assertEquals(sel.sampledGuards().toSet(), sel2.sampledGuards().toSet())
    }

    @Test
    fun `rotateGuard clears sample`(@TempDir dir: Path) {
        val config = TorConfig(dataDirectory = dir)
        val state = dir.resolve("guards")
        val sel = PathSelector(config, state)
        val relays = (1..5).map { i ->
            fakeGuard("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".replaceRange(0, 2, "%02X".format(i)), 100)
        } + listOf(fakeExit())
        sel.select(relays)
        assertTrue(sel.sampledGuards().isNotEmpty())
        sel.rotateGuard()
        assertTrue(sel.sampledGuards().isEmpty())
    }

    @Test
    fun `confirmGuard persists confirmed flag`(@TempDir dir: Path) {
        val config = TorConfig(dataDirectory = dir)
        val state = dir.resolve("guards")
        val sel = PathSelector(config, state)
        val relays = (1..5).map { i ->
            fakeGuard("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD".replaceRange(0, 2, "%02X".format(i)), 100)
        } + listOf(fakeExit())
        val path = sel.select(relays)
        sel.confirmGuard(path.guard.fingerprintHex)
        val sel2 = PathSelector(config, state)
        assertTrue(sel2.sampledEntries().any { it.fingerprintHex == path.guard.fingerprintHex && it.confirmed })
    }

    @Test
    fun `family note excludes shared members`(@TempDir dir: Path) {
        val config = TorConfig(dataDirectory = dir)
        val sel = PathSelector(config, dir.resolve("guards"))
        val g = fakeGuard("1111111111111111111111111111111111111111", 100)
        val m = fakeMiddle("2222222222222222222222222222222222222222")
        val e = fakeExit()
        sel.noteFamily(g.fingerprintHex, setOf(m.fingerprintHex))
        // Should still build a path (exit differs); middle may be replaced if only one middle.
        val path = sel.select(listOf(g, m, e, fakeMiddle("3333333333333333333333333333333333333333")))
        assertTrue(path.guard.fingerprintHex != path.middle.fingerprintHex)
        assertTrue(path.middle.fingerprintHex != path.exit.fingerprintHex)
    }

    @Test
    fun `longLivedPorts prefer Stable exit`(@TempDir dir: Path) {
        val config = TorConfig(dataDirectory = dir, longLivedPorts = setOf(22))
        val sel = PathSelector(config, dir.resolve("guards"))
        val g = fakeGuard("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 100)
        val mStable = fakeMiddle("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", stable = true)
        val mUnstable = fakeMiddle("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", stable = false)
        val eStable = fakeExit("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", stable = true)
        val eUnstable = fakeExit("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", stable = false, ip = "9.9.9.9")
        // Without exitPort: either exit ok. With 22: Stable preferred when available.
        repeat(20) {
            val path = sel.select(
                listOf(g, mStable, mUnstable, eStable, eUnstable),
                exitPort = 22,
            )
            assertTrue(path.exit.isStable, "expected Stable exit for LongLivedPorts")
            assertTrue(path.middle.isStable, "expected Stable middle for LongLivedPorts")
        }
    }

    private fun fakeGuard(fp: String, bw: Long) = RouterStatus(
        nickname = "G$fp".take(10),
        identity = org.kotlintor.util.hexToBytes(fp),
        digest = ByteArray(20),
        publication = java.time.Instant.EPOCH,
        ip = "1.2.3.4",
        orPort = 9001,
        dirPort = 0,
        flags = setOf("Running", "Fast", "Guard", "Stable", "Valid"),
        version = null,
        proto = emptyMap(),
        bandwidth = bw,
    )

    private fun fakeMiddle(fp: String, stable: Boolean = true) = RouterStatus(
        nickname = "M$fp".take(10),
        identity = org.kotlintor.util.hexToBytes(fp),
        digest = ByteArray(20),
        publication = java.time.Instant.EPOCH,
        ip = "9.9.9.${fp.take(2).toIntOrNull(16) ?: 1}",
        orPort = 9001,
        dirPort = 0,
        flags = buildSet {
            add("Running"); add("Fast"); add("Valid")
            if (stable) add("Stable")
        },
        version = null,
        proto = emptyMap(),
        bandwidth = 40,
    )

    private fun fakeExit(
        fp: String = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        stable: Boolean = true,
        ip: String = "5.6.7.8",
    ) = RouterStatus(
        nickname = "E$fp".take(10),
        identity = org.kotlintor.util.hexToBytes(fp),
        digest = ByteArray(20),
        publication = java.time.Instant.EPOCH,
        ip = ip,
        orPort = 9001,
        dirPort = 0,
        flags = buildSet {
            add("Running"); add("Fast"); add("Exit"); add("Valid")
            if (stable) add("Stable")
        },
        version = null,
        proto = emptyMap(),
        bandwidth = 50,
    )
}
