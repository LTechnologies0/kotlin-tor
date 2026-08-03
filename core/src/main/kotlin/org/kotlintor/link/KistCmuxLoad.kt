package org.kotlintor.link

import org.kotlintor.circuit.CircuitMux
import org.kotlintor.circuit.EwmaCircuitMuxPolicy

/**
 * Simulate multi-circuit cmux flush under a tight KIST write budget
 * (C Tor `scheduler_kist` + `circuitmux` under load lite).
 *
 * Enqueues [cellsPerCirc] cells on each of [nCircuits] circuits, then drains
 * via [CircuitMux.flush] gated by [WriteBudget] until empty or [maxRounds].
 */
object KistCmuxLoad {
    data class Result(
        val enqueued: Int,
        val flushed: Int,
        val deferred: Int,
        val rounds: Int,
        val budgetExhaustions: Int,
        val remainingCells: Int,
        val fairnessSpread: Double,
    )

    fun run(
        nCircuits: Int = 8,
        cellsPerCirc: Int = 16,
        cellBytes: Int = 514,
        tickBudgetBytes: Int = 2 * 514, // 2 cells/tick → forces multi-round drain
        maxRounds: Int = 512,
        halfLifeSec: Double = 30.0,
    ): Result {
        require(nCircuits > 0 && cellsPerCirc > 0)
        val mux = CircuitMux(EwmaCircuitMuxPolicy(halfLifeSec = halfLifeSec))
        val budget = WriteBudget(SchedulerType.KIST_LITE, tickBudgetBytes = tickBudgetBytes)
        val payload = ByteArray(cellBytes) { 0xab.toByte() }
        var enqueued = 0
        for (id in 1L..nCircuits.toLong()) {
            mux.attach(id)
            repeat(cellsPerCirc) {
                if (mux.enqueue(id, payload)) enqueued++
            }
        }
        val flushedPerCirc = LongArray(nCircuits + 1)
        var flushed = 0
        var deferred = 0
        var exhaustions = 0
        var rounds = 0
        while (mux.numCells() > 0 && rounds < maxRounds) {
            rounds++
            budget.refill(null)
            var progressed = false
            while (true) {
                val item = mux.flushNext() ?: break
                when (item) {
                    is CircuitMux.FlushItem.Destroy -> {
                        flushed++
                        progressed = true
                    }
                    is CircuitMux.FlushItem.Cell -> {
                        if (!budget.tryAllowFull(item.payload.size)) {
                            mux.enqueue(item.circId, item.payload)
                            deferred++
                            exhaustions++
                            break
                        }
                        flushed++
                        flushedPerCirc[item.circId.toInt()]++
                        progressed = true
                    }
                }
            }
            if (!progressed && mux.numCells() > 0) {
                // Force refill next round (simulates TCP_INFO tick).
                continue
            }
        }
        val counts = (1..nCircuits).map { flushedPerCirc[it].toDouble() }
        val mean = counts.average()
        val spread = if (mean == 0.0) 0.0 else counts.maxOrNull()!! - counts.minOrNull()!!
        return Result(
            enqueued = enqueued,
            flushed = flushed,
            deferred = deferred,
            rounds = rounds,
            budgetExhaustions = exhaustions,
            remainingCells = mux.numCells(),
            fairnessSpread = spread,
        )
    }
}
