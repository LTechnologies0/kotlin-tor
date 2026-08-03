package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.circuit.CircuitMux
import org.kotlintor.path.EntryGuardFsm
import org.kotlintor.path.PathBiasTracker

class VotingMuxPathBiasElevationTest {
    @Test
    fun `voting schedule phases`() {
        val now = 1_700_000_000L
        val sch = VotingSchedule.create(now, intervalSec = 300, voteDelaySec = 20, distDelaySec = 20)
        assertTrue(sch.intervalStartsEpochSec > now)
        assertEquals(VotingSchedule.Phase.IDLE, sch.phaseAt(now))
        assertEquals(VotingSchedule.Phase.VOTING, sch.phaseAt(sch.votingStartsEpochSec))
        assertEquals(VotingSchedule.Phase.DIST, sch.phaseAt(sch.votingEndsEpochSec))
        assertEquals(VotingSchedule.Phase.FETCHING, sch.phaseAt(sch.fetchingStartsEpochSec))
    }

    @Test
    fun `cmux flush prefers destroy then cells`() {
        val mux = CircuitMux()
        mux.attach(1, initialCells = 0)
        mux.enqueue(1, ByteArray(10) { 1 })
        mux.enqueue(1, ByteArray(10) { 2 })
        mux.queueDestroy(9, reason = 3)
        val first = mux.flushNext()
        assertTrue(first is CircuitMux.FlushItem.Destroy)
        assertEquals(9L, (first as CircuitMux.FlushItem.Destroy).circId)
        val second = mux.flushNext()
        assertTrue(second is CircuitMux.FlushItem.Cell)
        assertEquals(1L, (second as CircuitMux.FlushItem.Cell).circId)
        assertEquals(1, mux.circuitQueueSize(1))
    }

    @Test
    fun `pathbias drop notifies entry guard fsm`() {
        val fsm = EntryGuardFsm()
        val pb = PathBiasTracker(minCircs = 2, extremeRate = 0.99, dropGuards = true)
        pb.onGuardDropped = { fsm.disableForPathBias(it) }
        val fp = "aabbcc"
        repeat(3) { i ->
            pb.markBuildAttempted(i.toLong(), fp)
            // no success → rate 0 < extremeRate
        }
        assertEquals(PathBiasTracker.Level.EXTREME, pb.assess(fp))
        assertTrue(pb.isGuardDisabled(fp))
        assertTrue(fsm.getOrCreate(fp).pathBiasDisabled)
    }
}
