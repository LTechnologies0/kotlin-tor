package org.kotlintor.circuit

import org.kotlintor.cell.CircuitPurpose

/**
 * Circuit classification mirroring C Tor `origin_circuit_t` vs `or_circuit_t`.
 *
 * kotlin-tor keeps a single [Circuit] crypto/stream engine; these types carry
 * the purpose / hop-role metadata C Tor stores on the split structs.
 */
sealed class CircuitKind {
    abstract val purpose: CircuitPurpose
    abstract val circId: Long

    /**
     * Client/origin side (C Tor `origin_circuit_t`): path of n hops we built.
     */
    data class Origin(
        override val circId: Long,
        override val purpose: CircuitPurpose = CircuitPurpose.GENERAL,
        val pathLength: Int = 3,
        val isolationKey: String? = null,
        val buildStateMs: Long = System.currentTimeMillis(),
        var hasOpened: Boolean = false,
        var remainingRelayEarlyCells: Int = 8,
    ) : CircuitKind()

    /**
     * Relay/middle/exit side (C Tor `or_circuit_t`): p_chan / n_chan roles.
     */
    data class Or(
        override val circId: Long,
        override val purpose: CircuitPurpose = CircuitPurpose.OR,
        val nextCircId: Long? = null,
        val isExit: Boolean = false,
        val isDir: Boolean = false,
        var cryptoEstablished: Boolean = false,
    ) : CircuitKind()
}

/**
 * Attach kind metadata to a live [Circuit] without forking the crypto engine.
 */
class CircuitMeta(
    var kind: CircuitKind,
) {
    val isOrigin: Boolean get() = kind is CircuitKind.Origin
    val isOr: Boolean get() = kind is CircuitKind.Or
    val purpose: CircuitPurpose get() = kind.purpose
    /** C Tor circuitlist dirty bit (streams attached / used for exit). */
    @Volatile var dirty: Boolean = false
    /** C Tor `marked_for_close` — deferred removal via [CircuitList.closeAllMarked]. */
    @Volatile var markedForClose: Boolean = false
    @Volatile var state: CircuitState = CircuitState.BUILDING
    @Volatile var timestampCreatedMs: Long = System.currentTimeMillis()
    @Volatile var channelGid: Long = 0
    @Volatile var edgeStreamId: Long = 0
    @Volatile var testingCellStats: Int = 0
    @Volatile var pathLength: Int = (kind as? CircuitKind.Origin)?.pathLength ?: 0
    @Volatile var cpathOpenedLen: Int = 0
    val cpath: MutableList<ExtendInfo> = mutableListOf()
}
