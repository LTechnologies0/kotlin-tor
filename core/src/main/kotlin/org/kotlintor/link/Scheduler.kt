package org.kotlintor.link

/**
 * Channel write scheduler (C Tor `scheduler.c`).
 *
 * Inventory: `L1:core/or/scheduler.c`
 *
 * Types: [ChannelScheduler] / [SchedulerType]. Vanilla: [SchedulerVanilla].
 */
object Scheduler {
    @Volatile private var active: SchedulerType = SchedulerType.VANILLA
    @Volatile private var kistFullMode: Boolean = true
    @Volatile private var kistRunIntervalMs: Int = 10
    @Volatile private var bugOccurred: Boolean = false
    @Volatile private var initialized: Boolean = false
    @Volatile private var evActive: Boolean = false

    fun parseList(csv: String): List<SchedulerType> = ChannelScheduler.parseList(csv)

    fun select(preferred: List<SchedulerType>, tcpInfoOk: Boolean = true): SchedulerType =
        ChannelScheduler.select(preferred)

    fun defaultTypes(): List<SchedulerType> =
        listOf(SchedulerType.KIST, SchedulerType.KIST_LITE, SchedulerType.VANILLA)

    /** C Tor `scheduler_init`. */
    fun schedulerInit() {
        initialized = true
        bugOccurred = false
        active = SchedulerType.VANILLA
    }

    /** C Tor `scheduler_free_all`. */
    fun schedulerFreeAll() {
        ChannelSchedulerPending.clear()
        initialized = false
        evActive = false
    }

    /** C Tor `get_vanilla_scheduler`. */
    fun getVanillaScheduler(): SchedulerType = SchedulerType.VANILLA

    /** C Tor `get_kist_scheduler`. */
    fun getKistScheduler(): SchedulerType =
        if (kistFullMode) SchedulerType.KIST else SchedulerType.KIST_LITE

    /** C Tor `get_channels_pending`. */
    fun getChannelsPending(): Int = ChannelSchedulerPending.pendingCount()

    /** C Tor `get_scheduler_state_string`. */
    fun getSchedulerStateString(): String = when (active) {
        SchedulerType.NONE -> "none"
        SchedulerType.VANILLA -> "vanilla"
        SchedulerType.KIST -> "kist"
        SchedulerType.KIST_LITE -> "kist_lite"
    }

    /** C Tor `kist_scheduler_run_interval`. */
    fun kistSchedulerRunInterval(): Int = kistRunIntervalMs

    fun setKistRunIntervalForTests(ms: Int) {
        kistRunIntervalMs = ms.coerceAtLeast(1)
    }

    /** C Tor `scheduler_can_use_kist` — full KIST only when python probe is opted in. */
    fun schedulerCanUseKist(): Boolean = org.kotlintor.os.LinuxTcpInfo.isFullKistEnabled()

    /** C Tor `scheduler_kist_set_full_mode`. */
    fun schedulerKistSetFullMode() {
        kistFullMode = true
        active = SchedulerType.KIST
    }

    /** C Tor `scheduler_kist_set_lite_mode`. */
    fun schedulerKistSetLiteMode() {
        kistFullMode = false
        active = SchedulerType.KIST_LITE
    }

    /** C Tor `scheduler_bug_occurred`. */
    fun schedulerBugOccurred(): Boolean = bugOccurred

    fun noteBugForTests() {
        bugOccurred = true
    }

    /** C Tor `scheduler_channel_wants_writes`. */
    fun schedulerChannelWantsWrites(ch: OrChannel) {
        ChannelSchedulerPending.notePending(ch)
    }

    /** C Tor `scheduler_touch_channel`. */
    fun schedulerTouchChannel(ch: OrChannel) = schedulerChannelWantsWrites(ch)

    /** C Tor `scheduler_set_channel_state`. */
    fun schedulerSetChannelState(ch: OrChannel, state: ChannelSchedState) {
        ch.schedState = state
        if (state == ChannelSchedState.PENDING) schedulerChannelWantsWrites(ch)
    }

    /** C Tor `scheduler_conf_changed`. */
    fun schedulerConfChanged(preferred: List<SchedulerType> = defaultTypes()) {
        active = select(preferred)
    }

    /** C Tor `scheduler_notify_networkstatus_changed`. */
    fun schedulerNotifyNetworkstatusChanged() {
        if (active == SchedulerType.KIST && !schedulerCanUseKist()) {
            active = SchedulerType.KIST_LITE
        }
    }

    /** C Tor `scheduler_ev_add` / `scheduler_ev_active`. */
    fun schedulerEvAdd() {
        evActive = true
    }

    fun schedulerEvActive(): Boolean = evActive

    fun isInitialized(): Boolean = initialized
}
