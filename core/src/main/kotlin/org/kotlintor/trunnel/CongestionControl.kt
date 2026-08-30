package org.kotlintor.trunnel

/**
 * Congestion-control trunnel cells (C Tor `congestion_control.c` under trunnel/).
 *
 * Inventory: `L1:trunnel/congestion_control.c`
 *
 * Runtime CC: [org.kotlintor.circuit.CongestionControlCommon].
 */
object CongestionControl {
    const val TRUNNEL_UNIT: String = "congestion_control"
    fun known(): Boolean = true
}
