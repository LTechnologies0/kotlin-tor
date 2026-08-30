package org.kotlintor.dir

/**
 * Directory authority reachability testing (C Tor `reachability.c`).
 *
 * Inventory: `L1:feature/dirauth/reachability.c`
 *
 * Implementation: [ReachabilityTracker].
 */
object Reachability {
    private val sharedTracker = ReachabilityTracker()

    fun tracker(): ReachabilityTracker = ReachabilityTracker()

    fun defaultTracker(): ReachabilityTracker = sharedTracker

    fun shouldLaunchTest(
        tracker: ReachabilityTracker,
        newRi: ReachabilityTracker.Target,
        oldRi: ReachabilityTracker.Target?,
    ): Boolean = tracker.shouldLaunchTest(newRi, oldRi)

    /** C Tor `dirserv_should_launch_reachability_test`. */
    fun dirservShouldLaunchReachabilityTest(
        newRi: ReachabilityTracker.Target,
        oldRi: ReachabilityTracker.Target?,
        tracker: ReachabilityTracker = sharedTracker,
    ): Boolean = shouldLaunchTest(tracker, newRi, oldRi)

    /** C Tor `dirserv_orconn_tls_done`. */
    fun dirservOrconnTlsDone(
        identityHex: String,
        addr: String,
        orPort: Int,
        ed25519Hex: String? = null,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
        tracker: ReachabilityTracker = sharedTracker,
    ): Boolean = tracker.noteTlsDone(identityHex, addr, orPort, ed25519Hex, nowEpochSec)

    /**
     * C Tor `dirserv_single_reachability_test` — mark attempt and return whether to probe.
     */
    fun dirservSingleReachabilityTest(
        target: ReachabilityTracker.Target,
        tracker: ReachabilityTracker = sharedTracker,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ): Boolean {
        tracker.noteTarget(target)
        val due = tracker.dueForTest(nowEpochSec)
        return due.any { it.identityHex.equals(target.identityHex, ignoreCase = true) } ||
            dirservShouldLaunchReachabilityTest(target, null, tracker)
    }

    /**
     * C Tor `dirserv_test_reachability` — schedule due tests for current bucket.
     * Returns number of targets due.
     */
    fun dirservTestReachability(
        tracker: ReachabilityTracker = sharedTracker,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ): Int = tracker.dueForTest(nowEpochSec).size
}
