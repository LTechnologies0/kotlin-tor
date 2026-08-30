package org.kotlintor.link

/**
 * KIST scheduler helpers (C Tor `scheduler_kist.c`).
 *
 * Inventory: `L1:core/or/scheduler_kist.c`
 *
 * Socket-accounting budget math: [KistMath].
 */
object SchedulerKist {
    fun isKistFamily(t: SchedulerType): Boolean =
        t == SchedulerType.KIST || t == SchedulerType.KIST_LITE

    fun fallbackByteBudget(estimatedCells: Int = 32): Long = KistMath.liteLimit(estimatedCells)

    fun computeLimit(info: KistMath.SocketInfo): Long = KistMath.computeLimit(info)
}
