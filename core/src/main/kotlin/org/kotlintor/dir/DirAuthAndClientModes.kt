package org.kotlintor.dir

import org.kotlintor.config.TorConfig
import org.kotlintor.relay.RouterMode
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Directory-authority config + subsystem hooks (C Tor `dirauth_config` /
 * `dirauth_sys` / `dirauth_periodic`).
 *
 * Inventory: `L1:feature/dirauth/dirauth_config.c`, `dirauth_sys.c`, `dirauth_periodic.c`
 * `L2:feature/dirauth/dirauth_options_t`
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

object DirAuthSys {
    private val started = AtomicBoolean(false)
    private val voteActs = AtomicLong(0)

    fun shouldRunPublishLoop(config: TorConfig): Boolean =
        DirAuthOptions.fromTorConfig(config).enabled() && RouterMode.dirServerMode(config)

    fun timingFromConfig(config: TorConfig): DirVote.Timing {
        val o = DirAuthOptions.fromTorConfig(config)
        return DirVote.Timing(
            voteIntervalSec = o.votingIntervalSec.toInt().coerceAtLeast(DirVote.MIN_VOTE_INTERVAL),
            voteSeconds = o.voteDelaySec.toInt().coerceAtLeast(DirVote.MIN_VOTE_SECONDS),
            distSeconds = o.distDelaySec.toInt().coerceAtLeast(DirVote.MIN_DIST_SECONDS),
        )
    }

    fun init(config: TorConfig) {
        started.set(shouldRunPublishLoop(config))
    }

    fun shutdown() {
        started.set(false)
    }

    fun isStarted(): Boolean = started.get()

    fun noteVoteAct() {
        voteActs.incrementAndGet()
    }

    fun voteActCount(): Long = voteActs.get()
}

/**
 * Dirauth periodic event catalog (C Tor `dirauth_periodic.c`).
 */
object DirAuthPeriodic {
    fun scheduleHints(config: TorConfig): Map<String, Long> {
        val t = DirAuthSys.timingFromConfig(config)
        return mapOf(
            "vote_interval_sec" to t.voteIntervalSec.toLong(),
            "vote_delay_sec" to t.voteSeconds.toLong(),
            "dist_delay_sec" to t.distSeconds.toLong(),
            "check_descriptor_sec" to 60L,
        )
    }
}

/**
 * Directory client fetch-mode questions (C Tor `dirclient_modes.c`).
 *
 * Inventory: `L1:feature/dirclient/dirclient_modes.c`
 */
object DirClientModes {
    fun mustUseBegindir(config: TorConfig): Boolean = !RouterMode.publicServerMode(config)

    fun fetchesFromAuthorities(config: TorConfig): Boolean {
        if (config.fetchDirInfoEarly || config.fetchDirInfoExtraEarly) return true
        if (config.bridgeRelay) return false
        if (RouterMode.dirServerMode(config)) return true
        return false
    }

    fun fetchesDirInfoEarly(config: TorConfig): Boolean = fetchesFromAuthorities(config)

    fun fetchesDirInfoLater(config: TorConfig): Boolean = config.useBridges

    fun directoryFetchesV2(config: TorConfig): Boolean = false

    fun directoryFetchesV3(config: TorConfig): Boolean = true
}
