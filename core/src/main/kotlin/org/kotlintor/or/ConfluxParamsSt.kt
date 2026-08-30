package org.kotlintor.or

/** C Tor `conflux_params_t` struct mirror (runtime params live in [org.kotlintor.circuit.ConfluxParams]). */
data class ConfluxParamsSt(
    val enabled: Boolean = false,
    val maxLegs: Int = 2,
    val desiredUx: Int = 0,
)

@Deprecated("Use ConfluxParamsSt", ReplaceWith("ConfluxParamsSt"))
typealias ConfluxParamsMirror = ConfluxParamsSt
