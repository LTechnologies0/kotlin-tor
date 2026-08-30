package org.kotlintor.dir

import org.kotlintor.config.TorConfig
import org.kotlintor.relay.RouterMode
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Directory-authority subsystem lifecycle (C Tor `dirauth_sys.c`).
 *
 * Inventory: `L1:feature/dirauth/dirauth_sys.c`
 */
object DirAuthSys {
    private val started = AtomicBoolean(false)
    private val voteActs = AtomicLong(0)
    private val options = AtomicReference(DirAuthOptions())

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
        options.set(DirAuthOptions.fromTorConfig(config))
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

    /** C Tor `dirauth_get_options`. */
    fun dirauthGetOptions(): DirAuthOptions = options.get()

    /** C Tor `dirauth_set_options` — returns 0 on success. */
    fun dirauthSetOptions(opts: DirAuthOptions): Int {
        options.set(opts)
        return 0
    }
}
