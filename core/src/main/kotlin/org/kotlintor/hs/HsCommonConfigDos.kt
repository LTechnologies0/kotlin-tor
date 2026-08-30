package org.kotlintor.hs

import org.kotlintor.config.HiddenServiceConfig
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.Consensus
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * HS config surface (C Tor `hs_config.c` / `hs_opts_t`).
 * Inventory: `L1:feature/hs/hs_config.c`, `L2:feature/hs/hs_opts_t`
 */
data class HsOpts(
    val services: List<HiddenServiceConfig> = emptyList(),
    val nonAnonymousMode: Boolean = false,
    val singleHopMode: Boolean = false,
    val maxStreams: Int = 0,
    val powEnabled: Boolean = false,
) {
    fun validate(): List<String> {
        val errs = mutableListOf<String>()
        if (nonAnonymousMode && !singleHopMode) {
            errs += "HiddenServiceNonAnonymousMode requires SingleHopMode"
        }
        if (singleHopMode && !nonAnonymousMode) {
            errs += "HiddenServiceSingleHopMode requires NonAnonymousMode"
        }
        for (s in services) {
            if (s.numIntroductionPoints !in 1..20) {
                errs += "NumIntroductionPoints out of range for ${s.directory}"
            }
        }
        return errs
    }

    companion object {
        fun fromTorConfig(c: TorConfig): HsOpts =
            HsOpts(
                services = c.hiddenServices,
                nonAnonymousMode = c.hiddenServices.any { it.nonAnonymousMode },
                singleHopMode = c.hiddenServices.any { it.singleHopMode },
                maxStreams = c.hiddenServices.map { it.maxStreams }.maxOrNull() ?: 0,
                powEnabled = c.hiddenServices.any { it.powEnabled },
            )
    }
}

/**
 * Circuit / dir / edge HS identity tags (C Tor `hs_ident.c`).
 * Inventory: `L1:feature/hs/hs_ident.c`
 */
data class HsIdentCircuit(
    val serviceIdentityHex: String? = null,
    val blindedHex: String? = null,
    /** C Tor `intro_auth_pk` hex (required for valid intro circuits). */
    val introAuthKeyHex: String? = null,
    val isClient: Boolean = true,
    val purpose: String = "general",
)

data class HsIdentDirConn(
    val serviceIdentityHex: String,
    val hsDirIndexHint: String? = null,
    val purpose: String = "HS_HSDIR_FETCH",
)

/**
 * INTRODUCE2 DoS counters (C Tor `hs_dos.c`).
 * Inventory: `L1:feature/hs/hs_dos.c`
 *
 * Mirrors consensus params HiddenServiceEnableIntroDoS{Defense,RatePerSec,BurstPerSec}.
 */
class HsDosDefense(
    var ratePerSec: Int = DEFAULT_RATE,
    var burst: Int = DEFAULT_BURST,
    var enabled: Boolean = false,
) {
    private val counts = ConcurrentHashMap<String, AtomicInteger>()
    private var windowStartMs = System.currentTimeMillis()
    private val rejected = AtomicLong(0)

    /** Apply C Tor `hs_dos_consensus_has_changed` parameter set. */
    fun applyConsensus(consensus: Consensus?) {
        if (consensus == null) return
        enabled = consensus.param("HiddenServiceEnableIntroDoSDefense", 0) != 0L
        ratePerSec = consensus.param(
            "HiddenServiceEnableIntroDoSRatePerSec",
            DEFAULT_RATE.toLong(),
        ).toInt().coerceAtLeast(0)
        burst = consensus.param(
            "HiddenServiceEnableIntroDoSBurstPerSec",
            DEFAULT_BURST.toLong(),
        ).toInt().coerceAtLeast(0)
        if (burst < ratePerSec) burst = ratePerSec
    }

    /**
     * C Tor `hs_dos_can_send_intro2` analogue for service-side INTRODUCE2 admit.
     * When [enabled] is false, always admits (C default).
     */
    @Synchronized
    fun noteIntroduce(serviceKey: String): Boolean {
        if (!enabled) return true
        val now = System.currentTimeMillis()
        if (now - windowStartMs >= 1000) {
            counts.clear()
            windowStartMs = now
        }
        val n = counts.getOrPut(serviceKey) { AtomicInteger(0) }.incrementAndGet()
        val ok = n <= burst && (ratePerSec <= 0 || n <= ratePerSec.coerceAtLeast(1) * 4)
        if (!ok) rejected.incrementAndGet()
        return ok
    }

    fun rejectedCount(): Long = rejected.get()

    fun clear() {
        counts.clear()
        rejected.set(0)
    }

    companion object {
        const val DEFAULT_RATE: Int = 25
        const val DEFAULT_BURST: Int = 200

        /** Shared host-side defense used by [OnionServiceManager]. */
        val shared: HsDosDefense = HsDosDefense()
    }
}

/**
 * Intro-point bookkeeping FSM (C Tor `hs_intropoint.c`).
 * Inventory: `L1:feature/hs/hs_intropoint.c`
 */
enum class HsIntroFsm {
    NONE,
    ESTABLISHING,
    ESTABLISHED,
    INTRO_RECEIVED,
    CLOSED,
}

data class HsIntroPointState(
    val authKeyHex: String,
    var fsm: HsIntroFsm = HsIntroFsm.NONE,
    var established: Boolean = false,
    var introduceCount: Long = 0,
    var lastEstablishMs: Long = 0,
    var lastIntroduceMs: Long = 0,
    var circuitIdHint: String? = null,
)

class HsIntroPointTable {
    private val byAuth = ConcurrentHashMap<String, HsIntroPointState>()

    fun beginEstablish(authKeyHex: String, circuitIdHint: String? = null): HsIntroPointState {
        val k = authKeyHex.uppercase()
        val st = HsIntroPointState(
            authKeyHex = k,
            fsm = HsIntroFsm.ESTABLISHING,
            circuitIdHint = circuitIdHint,
        )
        byAuth[k] = st
        return st
    }

    fun noteEstablished(authKeyHex: String) {
        val k = authKeyHex.uppercase()
        val st = byAuth.getOrPut(k) { HsIntroPointState(k) }
        st.established = true
        st.fsm = HsIntroFsm.ESTABLISHED
        st.lastEstablishMs = System.currentTimeMillis()
    }

    fun noteIntroduce(authKeyHex: String) {
        byAuth[authKeyHex.uppercase()]?.let {
            it.introduceCount++
            it.lastIntroduceMs = System.currentTimeMillis()
            if (it.fsm == HsIntroFsm.ESTABLISHED || it.fsm == HsIntroFsm.INTRO_RECEIVED) {
                it.fsm = HsIntroFsm.INTRO_RECEIVED
            }
        }
    }

    fun noteClosed(authKeyHex: String) {
        byAuth[authKeyHex.uppercase()]?.let {
            it.established = false
            it.fsm = HsIntroFsm.CLOSED
        }
    }

    fun get(authKeyHex: String): HsIntroPointState? = byAuth[authKeyHex.uppercase()]

    fun establishedCount(): Int = byAuth.values.count { it.established }

    fun size(): Int = byAuth.size

    fun clear() = byAuth.clear()
}
