package org.kotlintor.dir

/**
 * Directory authority mode predicates (C Tor `authmode.c` / `authmode.h`).
 *
 * Inventory: `L1:feature/dirauth/authmode.c`
 */
data class AuthModeOptions(
    val authoring: Boolean = false,
    val v3: Boolean = true,
    val bridgeAuthority: Boolean = false,
    val publishStatuses: Boolean = true,
    val testReachability: Boolean = true,
    val handleDescriptors: Boolean = true,
)

object AuthMode {
    fun isAuthority(opts: AuthModeOptions): Boolean = opts.authoring
    fun isV3(opts: AuthModeOptions): Boolean = opts.authoring && opts.v3
    fun isBridge(opts: AuthModeOptions): Boolean = opts.authoring && opts.bridgeAuthority
    fun handlesDescs(opts: AuthModeOptions, purpose: Int = PURPOSE_GENERAL): Boolean {
        if (!opts.authoring || !opts.handleDescriptors) return false
        if (opts.bridgeAuthority) return purpose == PURPOSE_BRIDGE
        return purpose == PURPOSE_GENERAL || purpose == PURPOSE_BRIDGE
    }
    fun publishesStatuses(opts: AuthModeOptions): Boolean =
        opts.authoring && opts.publishStatuses
    fun testsReachability(opts: AuthModeOptions): Boolean =
        opts.authoring && opts.testReachability

    /** C Tor `authdir_mode`. */
    fun authdirMode(opts: AuthModeOptions): Boolean = isAuthority(opts)

    /** C Tor `authdir_mode_v3`. */
    fun authdirModeV3(opts: AuthModeOptions): Boolean = isV3(opts)

    /** C Tor `authdir_mode_bridge`. */
    fun authdirModeBridge(opts: AuthModeOptions): Boolean = isBridge(opts)

    /** C Tor `authdir_mode_handles_descs`. */
    fun authdirModeHandlesDescs(opts: AuthModeOptions, purpose: Int = PURPOSE_GENERAL): Boolean =
        handlesDescs(opts, purpose)

    /** C Tor `authdir_mode_publishes_statuses`. */
    fun authdirModePublishesStatuses(opts: AuthModeOptions): Boolean = publishesStatuses(opts)

    /** C Tor `authdir_mode_tests_reachability`. */
    fun authdirModeTestsReachability(opts: AuthModeOptions): Boolean = testsReachability(opts)

    const val PURPOSE_GENERAL: Int = 0
    const val PURPOSE_BRIDGE: Int = 1
}
