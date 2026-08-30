package org.kotlintor.hs

import org.kotlintor.dir.Consensus

/**
 * INTRODUCE2 DoS defense (C Tor `hs_dos.c`).
 *
 * Inventory: `L1:feature/hs/hs_dos.c`
 *
 * Implementation: [HsDosDefense].
 */
object HsDos {
    const val DEFAULT_RATE: Int = HsDosDefense.DEFAULT_RATE
    const val DEFAULT_BURST: Int = HsDosDefense.DEFAULT_BURST

    fun shared(): HsDosDefense = HsDosDefense.shared
    fun applyConsensus(consensus: Consensus?) = shared().applyConsensus(consensus)
    fun noteIntroduce(serviceKey: String): Boolean = shared().noteIntroduce(serviceKey)

    /** C Tor `get_intro2_rate_consensus_param`. */
    fun getIntro2RateConsensusParam(consensus: Consensus?): Int =
        consensus?.param("HiddenServiceEnableIntroDoSRatePerSec", DEFAULT_RATE.toLong())?.toInt()
            ?: DEFAULT_RATE

    /** C Tor `get_intro2_burst_consensus_param`. */
    fun getIntro2BurstConsensusParam(consensus: Consensus?): Int =
        consensus?.param("HiddenServiceEnableIntroDoSBurstPerSec", DEFAULT_BURST.toLong())?.toInt()
            ?: DEFAULT_BURST

    /** C Tor `get_intro2_enable_consensus_param`. */
    fun getIntro2EnableConsensusParam(consensus: Consensus?): Boolean =
        (consensus?.param("HiddenServiceEnableIntroDoSDefense", 0) ?: 0) != 0L

    /** C Tor `hs_dos_can_send_intro2`. */
    fun hsDosCanSendIntro2(serviceKey: String): Boolean = noteIntroduce(serviceKey)

    /** C Tor `hs_dos_consensus_has_changed`. */
    fun hsDosConsensusHasChanged(consensus: Consensus?) = applyConsensus(consensus)

    /** C Tor `hs_dos_get_intro2_rejected_count`. */
    fun hsDosGetIntro2RejectedCount(): Long = shared().rejectedCount()

    /** C Tor `hs_dos_init`. */
    fun hsDosInit() {
        shared().clear()
        hsDosSetupDefaultIntro2Defenses()
    }

    /** C Tor `hs_dos_setup_default_intro2_defenses` — defaults; enable from consensus separately. */
    fun hsDosSetupDefaultIntro2Defenses() {
        val d = shared()
        d.ratePerSec = DEFAULT_RATE
        d.burst = DEFAULT_BURST
        // C Tor enables from consensus param on circuit; leave enabled as currently set.
        if (d.burst < d.ratePerSec) d.burst = d.ratePerSec
    }
}
