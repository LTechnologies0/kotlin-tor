package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.TorrcParser
import org.kotlintor.dir.TorDaemonDirAuthCluster
import org.kotlintor.link.KistCmuxLoad
import org.kotlintor.path.PathBiasTracker
import java.nio.file.Path
import kotlin.io.path.createTempDirectory

class KistPathBiasLiveDirAuthElevationTest {
    @Test
    fun `KIST cmux drains under load with budget exhaustions`() {
        val r = KistCmuxLoad.run(
            nCircuits = 8,
            cellsPerCirc = 12,
            tickBudgetBytes = 514, // 1 cell/tick
            maxRounds = 256,
        )
        assertEquals(8 * 12, r.enqueued)
        assertEquals(r.enqueued, r.flushed)
        assertEquals(0, r.remainingCells)
        assertTrue(r.budgetExhaustions > 0, "expected KIST budget pressure")
        assertTrue(r.rounds > 8, "tight budget should need many rounds")
        // EWMA fairness: no circuit starved by more than half the mean under load
        assertTrue(r.fairnessSpread <= 12.0, "fairnessSpread=${r.fairnessSpread}")
    }

    @Test
    fun `PathBias options typed and assess use rates`() {
        val cfg = TorrcParser.parse(
            """
            DataDirectory /tmp/kt
            PathBiasCircThreshold 10
            PathBiasNoticeRate 0.9
            PathBiasWarnRate 0.6
            PathBiasExtremeRate 0.4
            PathBiasUseThreshold 5
            PathBiasNoticeUseRate 0.85
            PathBiasExtremeUseRate 0.5
            PathBiasScaleThreshold 50
            PathBiasDropGuards 1
            """.trimIndent(),
            Path.of("/tmp/kt"),
        )
        assertEquals(10, cfg.pathBias.circThreshold)
        assertEquals(0.9, cfg.pathBias.noticeRate, 1e-9)
        assertEquals(0.4, cfg.pathBias.extremeRate, 1e-9)
        assertTrue(cfg.pathBias.dropGuards)
        assertTrue(cfg.pathBiasDropGuards)
        val t = PathBiasTracker(cfg.pathBias)
        assertTrue(t.dropGuards)
        repeat(10) { i ->
            t.markBuildAttempted(i.toLong(), "aa")
            if (i < 3) t.markBuildSucceeded(i.toLong(), "aa")
        }
        assertEquals(PathBiasTracker.Level.EXTREME, t.assess("aa"))
    }

    @Test
    fun `live DirAuthPublishLoop gossip reaches quorum`() {
        val dir = createTempDirectory("ktor-live-dirauth")
        val cluster = TorDaemonDirAuthCluster(dir, nAuthorities = 3)
        val result = cluster.runLivePublishQuorum(timeoutMs = 8_000)
        assertTrue(result.quorum, "live publish loops should merge to quorum")
        assertTrue(result.consensusBytes > 0)
        assertEquals(3, result.fingerprints.size)
    }
}
