package org.kotlintor.circuit

import org.kotlintor.cell.RelayCell
import org.kotlintor.cell.RelayCommand
import org.kotlintor.util.SecureRandomSource

/**
 * Prop302 / C Tor `circuitpadding_machines.c` — HS intro/rend hide machines.
 *
 * Full WTF-PAD state machine remains thinner; this encodes the published
 * machine names, hop targets, and DROP-cell burst bounds used by C Tor.
 */
object CircuitPaddingMachines {
    /** C Tor `INTRO_MACHINE_MINIMUM_PADDING` / `INTRO_MACHINE_MAXIMUM_PADDING`. */
    const val INTRO_MACHINE_MINIMUM_PADDING: Int = 7
    const val INTRO_MACHINE_MAXIMUM_PADDING: Int = 10

    enum class Kind {
        CLIENT_INTRO,
        CLIENT_REND,
        RELAY_INTRO,
        RELAY_REND,
    }

    data class Spec(
        val name: String,
        val kind: Kind,
        val originSide: Boolean,
        /** 1-based hop index for padding (C Tor `target_hopnum`). */
        val targetHopNum: Int,
        val minPaddingCells: Int,
        val maxPaddingCells: Int,
        val conditions: CircpadMachineConditions = CircpadMachineConditions(),
    )

    fun clientHideIntro(): Spec =
        Spec(
            name = "client_ip_circ",
            kind = Kind.CLIENT_INTRO,
            originSide = true,
            targetHopNum = 2,
            minPaddingCells = INTRO_MACHINE_MINIMUM_PADDING,
            maxPaddingCells = INTRO_MACHINE_MAXIMUM_PADDING,
            conditions = CircpadMachineConditions.introClient(),
        )

    fun clientHideRend(): Spec =
        Spec(
            name = "client_rp_circ",
            kind = Kind.CLIENT_REND,
            originSide = true,
            targetHopNum = 2,
            minPaddingCells = INTRO_MACHINE_MINIMUM_PADDING,
            maxPaddingCells = INTRO_MACHINE_MAXIMUM_PADDING,
            conditions = CircpadMachineConditions.rendClient(),
        )

    fun relayHideIntro(): Spec =
        Spec(
            name = "relay_ip_circ",
            kind = Kind.RELAY_INTRO,
            originSide = false,
            targetHopNum = 1,
            minPaddingCells = INTRO_MACHINE_MINIMUM_PADDING,
            maxPaddingCells = INTRO_MACHINE_MAXIMUM_PADDING,
            conditions = CircpadMachineConditions.relaySide(),
        )

    fun relayHideRend(): Spec =
        Spec(
            name = "relay_rp_circ",
            kind = Kind.RELAY_REND,
            originSide = false,
            targetHopNum = 1,
            minPaddingCells = INTRO_MACHINE_MINIMUM_PADDING,
            maxPaddingCells = INTRO_MACHINE_MAXIMUM_PADDING,
            conditions = CircpadMachineConditions.relaySide(),
        )

    fun allBuiltin(): List<Spec> =
        listOf(clientHideIntro(), clientHideRend(), relayHideIntro(), relayHideRend())

    /**
     * First builtin machine whose [CircpadMachineConditions.mayApply] matches
     * (C Tor iterates machine lists in priority order).
     */
    fun selectApplicable(
        hopCount: Int,
        circFlags: Int,
        purposeMask: Int = CircpadMachineConditions.PURPOSE_ALL,
        vanguardsEnabled: Boolean = false,
        reducedPadding: Boolean = false,
        originSide: Boolean = true,
    ): Spec? =
        allBuiltin()
            .filter { it.originSide == originSide }
            .firstOrNull {
                it.conditions.mayApply(
                    hopCount = hopCount,
                    circFlags = circFlags,
                    purposeMask = purposeMask,
                    vanguardsEnabled = vanguardsEnabled,
                    reducedPadding = reducedPadding,
                )
            }

    /** Sample padding cell count uniformly in [min, max] inclusive (C Tor). */
    fun samplePaddingCount(spec: Spec): Int {
        val span = spec.maxPaddingCells - spec.minPaddingCells + 1
        require(span > 0)
        return spec.minPaddingCells + SecureRandomSource.nextInt(span)
    }

    /** Build RELAY DROP cells for one machine burst (empty body). */
    fun dropCells(count: Int): List<RelayCell> {
        require(count >= 0)
        return List(count) { RelayCell.build(RelayCommand.DROP, 0, ByteArray(0)) }
    }
}

/**
 * Lightweight runtime for one padding machine on a circuit.
 * Call [onIntroduce1Sent] (client intro) to arm DROP bursts; optionally
 * [negotiateStart] / [onNegotiated] for RELAY PADDING_NEGOTIATE/D (prop302).
 */
class CircuitPaddingSession(
    private val spec: CircuitPaddingMachines.Spec,
    private val sendDrop: suspend (RelayCell) -> Unit,
    private val sendNegotiate: (suspend (RelayCell) -> Unit)? = null,
) {
    private var armed = false
    private var sent = 0
    private var target = 0
    private var machineCtr: Long = 1
    private val negotiateSession = CircpadNegotiateSession(
        machineFactory = { CircpadStateMachine(CircpadStateMachine.wtfPadLite()) },
    )
    var negotiatedOk: Boolean = false
        private set

    suspend fun negotiateStart(machineCtr: Long = this.machineCtr) {
        val send = sendNegotiate ?: return
        this.machineCtr = machineCtr
        send(CircpadNegotiate.startCell(machineCtr = machineCtr))
    }

    fun onNegotiated(body: ByteArray): Boolean {
        negotiatedOk = negotiateSession.handleNegotiated(body)
        return negotiatedOk
    }

    fun onIntroduce1Sent() {
        if (spec.kind != CircuitPaddingMachines.Kind.CLIENT_INTRO) return
        if (armed) return
        armed = true
        target = CircuitPaddingMachines.samplePaddingCount(spec)
        negotiateSession.machine?.onEvent(Circpad.Event.NONPADDING_SENT)
    }

    /**
     * Live middle-hop ACK path (prop302): advance padding FSM on non-padding received.
     * Additional WTF-PAD machine tables remain thinner; this wires the ACK event into the session FSM.
     */
    fun onMiddleNonPaddingReceived() {
        negotiateSession.machine?.onEvent(Circpad.Event.NONPADDING_RECV)
    }

    fun onMiddlePaddingReceived() {
        negotiateSession.machine?.onEvent(Circpad.Event.PADDING_RECV)
    }

    fun onRendezvousEstablished() {
        if (spec.kind != CircuitPaddingMachines.Kind.CLIENT_REND) return
        if (armed) return
        armed = true
        target = CircuitPaddingMachines.samplePaddingCount(spec)
    }

    suspend fun flushPendingDrops() {
        if (!armed || sent >= target) return
        while (sent < target) {
            sendDrop(RelayCell.build(RelayCommand.DROP, 0, ByteArray(0)))
            sent++
            negotiateSession.machine?.onPaddingSent()
        }
    }

    val remaining: Int get() = (target - sent).coerceAtLeast(0)
    val isComplete: Boolean get() = armed && sent >= target
}
