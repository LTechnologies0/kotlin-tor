package org.kotlintor.link

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ChannelSchedulerTest {
    @Test
    fun `parse and select prefer KIST`() {
        val list = ChannelScheduler.parseList("KIST,KISTLite,Vanilla")
        assertEquals(
            listOf(SchedulerType.KIST, SchedulerType.KIST_LITE, SchedulerType.VANILLA),
            list,
        )
        assertEquals(SchedulerType.KIST, ChannelScheduler.select(list))
    }

    @Test
    fun `WriteBudget KIST_LITE caps then refills`() {
        val b = WriteBudget(SchedulerType.KIST_LITE, tickBudgetBytes = 100)
        b.refill()
        assertEquals(60, b.allow(60))
        assertEquals(40, b.allow(100))
        assertEquals(0, b.allow(10))
        b.refill()
        assertEquals(100, b.allow(100))
    }

    @Test
    fun `Vanilla unlimited`() {
        val b = WriteBudget(SchedulerType.VANILLA)
        b.refill()
        assertEquals(1_000_000, b.allow(1_000_000))
    }
}
