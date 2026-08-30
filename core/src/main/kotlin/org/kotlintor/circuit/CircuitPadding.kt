package org.kotlintor.circuit

/**
 * Circuit padding (C Tor `circuitpadding.c`).
 *
 * Inventory: `L1:core/or/circuitpadding.c`
 *
 * FSM primitives: [Circpad]. Machine tables: [CircuitPaddingMachines].
 */
object CircuitPadding {
    val DELAY_UNITS_PER_SECOND: Long = Circpad.DELAY_UNITS_PER_SECOND

    fun delayInfinite(): Long = Circpad.DELAY_INFINITE

    fun buildingState(): Int = Circpad.CircState.BUILDING

    fun openedState(): Int = Circpad.CircState.OPENED

    fun clientHideIntro() = CircuitPaddingMachines.clientHideIntro()

    fun clientHideRend() = CircuitPaddingMachines.clientHideRend()

    // --- C Tor circuitpadding.h cell-event aliases (L3) ---

    data class MachineInfo(var machines: MutableList<CircuitPaddingMachines.Spec> = mutableListOf())

    private val matching = mutableListOf<CircuitPaddingMachines.Spec>()

    /** C Tor `circpad_add_matching_machines`. */
    fun circpadAddMatchingMachines(specs: List<CircuitPaddingMachines.Spec>) {
        matching.clear()
        matching.addAll(specs)
    }

    /** C Tor `circpad_cell_event_nonpadding_received`. */
    fun circpadCellEventNonpaddingReceived(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.NONPADDING_RECV)

    /** C Tor `circpad_cell_event_nonpadding_sent`. */
    fun circpadCellEventNonpaddingSent(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.NONPADDING_SENT)

    /** C Tor `circpad_cell_event_padding_received`. */
    fun circpadCellEventPaddingReceived(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.PADDING_RECV)

    /** C Tor `circpad_cell_event_padding_sent`. */
    fun circpadCellEventPaddingSent(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.PADDING_SENT)

    /** C Tor `circpad_check_received_cell` — DROP vs non-padding. */
    fun circpadCheckReceivedCell(isPadding: Boolean): Circpad.Event =
        if (isPadding) Circpad.Event.PADDING_RECV else Circpad.Event.NONPADDING_RECV

    /** C Tor `circpad_circ_purpose_to_mask`. */
    fun circpadCircPurposeToMask(purpose: org.kotlintor.cell.CircuitPurpose): Int =
        CircpadMachineConditions.PURPOSE_ALL

    /** C Tor `circpad_circuit_free_all_machineinfos`. */
    fun circpadCircuitFreeAllMachineinfos(info: MachineInfo) {
        info.machines.clear()
    }

    /** C Tor `circpad_circuit_machineinfo_new`. */
    fun circpadCircuitMachineinfoNew(): MachineInfo = MachineInfo()

    /** C Tor `circpad_deliver_recognized_relay_cell_events`. */
    fun circpadDeliverRecognizedRelayCellEvents(ctrl: CircpadMachineController, isPadding: Boolean) =
        if (isPadding) circpadCellEventPaddingReceived(ctrl) else circpadCellEventNonpaddingReceived(ctrl)

    /** C Tor `circpad_deliver_sent_relay_cell_events`. */
    fun circpadDeliverSentRelayCellEvents(ctrl: CircpadMachineController, isPadding: Boolean) =
        if (isPadding) circpadCellEventPaddingSent(ctrl) else circpadCellEventNonpaddingSent(ctrl)

    /** C Tor `circpad_deliver_unrecognized_cell_events`. */
    fun circpadDeliverUnrecognizedCellEvents(ctrl: CircpadMachineController) =
        circpadCellEventNonpaddingReceived(ctrl)

    fun matchingMachines(): List<CircuitPaddingMachines.Spec> = matching.toList()

    // --- remaining circuitpadding.h L3 aliases ---

    /** C Tor `circpad_free_all`. */
    fun circpadFreeAll() {
        matching.clear()
    }

    /** C Tor `circpad_handle_padding_negotiate`. */
    fun circpadHandlePaddingNegotiate(body: ByteArray): CircpadNegotiate.Negotiate =
        CircpadNegotiate.parseNegotiate(body)

    /** C Tor `circpad_handle_padding_negotiated`. */
    fun circpadHandlePaddingNegotiated(body: ByteArray): CircpadNegotiate.Negotiated =
        CircpadNegotiate.parseNegotiated(body)

    /** C Tor `circpad_histogram_bin_to_usec`. */
    fun circpadHistogramBinToUsec(hist: CircpadHistogram, bin: Int): Long =
        hist.binToUsec(bin)

    /** C Tor `circpad_histogram_usec_to_bin`. */
    fun circpadHistogramUsecToBin(hist: CircpadHistogram, usec: Long): Int =
        hist.binForDelay(usec)

    /** C Tor `circpad_internal_event_bins_empty`. */
    fun circpadInternalEventBinsEmpty(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.BINS_EMPTY)

    /** C Tor `circpad_internal_event_infinity`. */
    fun circpadInternalEventInfinity(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.INFINITY)

    /** C Tor `circpad_internal_event_state_length_up`. */
    fun circpadInternalEventStateLengthUp(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.LENGTH_COUNT)

    /** C Tor `circpad_machine_current_state`. */
    fun circpadMachineCurrentState(ctrl: CircpadMachineController): Int = ctrl.runtime.stateIndex

    /** C Tor `circpad_machine_event_circ_added_hop`. */
    fun circpadMachineEventCircAddedHop(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.NONPADDING_SENT, Circpad.CircState.BUILDING)

    /** C Tor `circpad_machine_event_circ_built`. */
    fun circpadMachineEventCircBuilt(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.NONPADDING_SENT, Circpad.CircState.OPENED)

    /** C Tor `circpad_machine_event_circ_has_no_relay_early`. */
    fun circpadMachineEventCircHasNoRelayEarly(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.NONPADDING_SENT, Circpad.CircState.HAS_NO_RELAY_EARLY)

    /** C Tor `circpad_machine_event_circ_has_no_streams`. */
    fun circpadMachineEventCircHasNoStreams(ctrl: CircpadMachineController): Circpad.Decision =
        ctrl.onEvent(Circpad.Event.NONPADDING_SENT, Circpad.CircState.NO_STREAMS)

    /** C Tor `circpad_machine_client_hide_intro_circuits`. */
    fun circpadMachineClientHideIntroCircuits(): CircuitPaddingMachines.Spec = clientHideIntro()

    /** C Tor `circpad_machine_client_hide_rend_circuits`. */
    fun circpadMachineClientHideRendCircuits(): CircuitPaddingMachines.Spec = clientHideRend()

    /** C Tor `circpad_machine_relay_hide_intro_circuits`. */
    fun circpadMachineRelayHideIntroCircuits(): CircuitPaddingMachines.Spec =
        CircuitPaddingMachines.relayHideIntro()

    /** C Tor `circpad_machine_relay_hide_rend_circuits`. */
    fun circpadMachineRelayHideRendCircuits(): CircuitPaddingMachines.Spec =
        CircuitPaddingMachines.relayHideRend()
}
