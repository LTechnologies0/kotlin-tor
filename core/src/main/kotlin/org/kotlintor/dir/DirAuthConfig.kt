package org.kotlintor.dir

import org.kotlintor.config.TorConfig

/**
 * Directory-authority options (C Tor `dirauth_config.c` / `dirauth_options_t`).
 *
 * Inventory: `L1:feature/dirauth/dirauth_config.c`
 */
data class DirAuthOptions(
    val authoritativeDirectory: Boolean = false,
    val v3AuthoritativeDirectory: Boolean = false,
    val bridgeAuthoritativeDir: Boolean = false,
    val votingIntervalSec: Long = 300,
    val voteDelaySec: Long = 20,
    val distDelaySec: Long = 20,
    val authDirShareBandwidth: Boolean = true,
    val authDirMaxServersPerAddr: Int = 2,
    val authDirListBadExits: Boolean = false,
) {
    fun enabled(): Boolean =
        authoritativeDirectory || v3AuthoritativeDirectory || bridgeAuthoritativeDir

    fun validate(): List<String> {
        val errs = mutableListOf<String>()
        if (enabled() && votingIntervalSec < DirVote.MIN_VOTE_INTERVAL) {
            errs += "V3AuthVotingInterval too low"
        }
        return errs
    }

    companion object {
        fun fromTorConfig(c: TorConfig): DirAuthOptions =
            DirAuthOptions(
                authoritativeDirectory = c.authoritativeDirectory,
                v3AuthoritativeDirectory = c.v3AuthoritativeDirectory,
                bridgeAuthoritativeDir = c.bridgeAuthoritativeDir,
                votingIntervalSec = c.runtime.v3AuthVotingIntervalSec.toLong(),
                voteDelaySec = c.runtime.v3AuthVoteDelaySec.toLong(),
                distDelaySec = c.runtime.v3AuthDistDelaySec.toLong(),
            )
    }
}

/**
 * Naming primary for `dirauth_config.c`.
 */
object DirAuthConfig {
    fun fromTorConfig(c: TorConfig): DirAuthOptions = DirAuthOptions.fromTorConfig(c)

    fun enabled(c: TorConfig): Boolean = fromTorConfig(c).enabled()

    fun validate(c: TorConfig): List<String> = fromTorConfig(c).validate()

    @Volatile
    private var rejectUnderLoad: Boolean = false

    /** C Tor `dirauth_should_reject_requests_under_load`. */
    fun dirauthShouldRejectRequestsUnderLoad(): Boolean = rejectUnderLoad

    fun setRejectRequestsUnderLoad(reject: Boolean) {
        rejectUnderLoad = reject
    }

    /** C Tor `options_act_dirauth` — apply options; return 0 on success. */
    fun optionsActDirauth(opts: DirAuthOptions): Int {
        if (opts.validate().isNotEmpty()) return -1
        return 0
    }

    /** C Tor `options_act_dirauth_mtbf`. */
    fun optionsActDirauthMtbf(opts: DirAuthOptions): Int = optionsActDirauth(opts)

    /** C Tor `options_act_dirauth_stats`. */
    fun optionsActDirauthStats(opts: DirAuthOptions): Int = optionsActDirauth(opts)

    /** C Tor `options_validate_dirauth_mode`. */
    fun optionsValidateDirauthMode(opts: DirAuthOptions): List<String> = opts.validate()

    /** C Tor `options_validate_dirauth_schedule`. */
    fun optionsValidateDirauthSchedule(opts: DirAuthOptions): List<String> {
        val errs = mutableListOf<String>()
        if (opts.voteDelaySec + opts.distDelaySec >= opts.votingIntervalSec) {
            errs += "vote+dist delay must fit in voting interval"
        }
        return errs
    }

    /** C Tor `options_validate_dirauth_testing`. */
    fun optionsValidateDirauthTesting(opts: DirAuthOptions): List<String> {
        val errs = mutableListOf<String>()
        if (opts.enabled() && opts.votingIntervalSec < DirVote.MIN_VOTE_INTERVAL_TESTING) {
            errs += "testing voting interval too low"
        }
        return errs
    }
}
