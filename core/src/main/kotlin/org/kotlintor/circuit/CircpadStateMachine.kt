package org.kotlintor.circuit

/**
 * Multi-state WTF-PAD machine runtime from C Tor `circpad_state_t` /
 * `circpad_machine_runtime_t` (`circuitpadding.h`).
 *
 * States START / BURST / GAP occupy the state array; END / IGNORE / CANCEL are
 * pseudo-states that do not occupy slots. Transitions are driven by
 * [Circpad.Event] via per-state `next_state[]`.
 */
object CircpadStates {
    const val START: Int = 0
    const val BURST: Int = 1
    const val GAP: Int = 2

    /** `CIRCPAD_STATENUM_MAX` stand-in for END (pseudo). */
    const val END: Int = 0xFFFF
    const val IGNORE: Int = END - 1
    const val CANCEL: Int = END - 2

    const val NUM_EVENTS: Int = 7
}

data class CircpadStateDef(
    val name: String,
    /** Per [Circpad.Event.ordinal] next state index / pseudo-state. */
    val nextState: IntArray,
    val histogram: CircpadHistogram? = null,
    val lengthIncludesNonpadding: Boolean = true,
) {
    init {
        require(nextState.size == CircpadStates.NUM_EVENTS) {
            "nextState must cover CIRCPAD_NUM_EVENTS=${CircpadStates.NUM_EVENTS}"
        }
    }
}

data class CircpadMachineSpec(
    val name: String,
    val states: List<CircpadStateDef>,
    val targetHopNum: Int = 2,
    val originSide: Boolean = true,
    val allowedPaddingCount: Int = 100,
    val maxPaddingPercent: Int = 0,
    val conditions: CircpadMachineConditions = CircpadMachineConditions(),
) {
    init {
        require(states.isNotEmpty())
        require(states.size <= CircpadStates.CANCEL - 1)
    }
}

/**
 * Runtime: current state index, remaining length tokens, padding counters.
 * Call [onEvent] then [sampleNextDelayUs] to schedule DROPs.
 */
class CircpadStateMachine(
    private val spec: CircpadMachineSpec,
) {
    var stateIndex: Int = CircpadStates.START
        private set
    var paddingSent: Int = 0
        private set
    var ended: Boolean = false
        private set
    var cancelled: Boolean = false
        private set
    var nextDelayUs: Long = Circpad.DELAY_INFINITE
        private set

    fun current(): CircpadStateDef = spec.states[stateIndex.coerceIn(0, spec.states.lastIndex)]

    fun onEvent(event: Circpad.Event): Circpad.Decision {
        if (ended || cancelled) return Circpad.Decision.UNCHANGED
        val cur = current()
        val dest = cur.nextState[event.ordinal]
        return when (dest) {
            CircpadStates.IGNORE -> Circpad.Decision.UNCHANGED
            CircpadStates.CANCEL -> {
                cancelled = true
                nextDelayUs = Circpad.DELAY_INFINITE
                Circpad.Decision.CHANGED
            }
            CircpadStates.END -> {
                ended = true
                nextDelayUs = Circpad.DELAY_INFINITE
                Circpad.Decision.CHANGED
            }
            else -> {
                if (dest !in spec.states.indices) return Circpad.Decision.UNCHANGED
                val changed = dest != stateIndex
                stateIndex = dest
                val hist = spec.states[stateIndex].histogram
                hist?.refill()
                nextDelayUs = hist?.sampleDelayUs() ?: Circpad.DELAY_INFINITE
                if (changed) Circpad.Decision.CHANGED else Circpad.Decision.UNCHANGED
            }
        }
    }

    /** After a padding cell is sent, apply PADDING_SENT transition. */
    fun onPaddingSent(): Circpad.Decision {
        paddingSent++
        if (paddingSent >= spec.allowedPaddingCount) {
            ended = true
            nextDelayUs = Circpad.DELAY_INFINITE
            return Circpad.Decision.CHANGED
        }
        return onEvent(Circpad.Event.PADDING_SENT)
    }

    fun sampleNextDelayUs(): Long {
        if (ended || cancelled) return Circpad.DELAY_INFINITE
        val hist = current().histogram ?: return nextDelayUs
        nextDelayUs = hist.sampleDelayUs()
        if (hist.binsEmpty()) onEvent(Circpad.Event.BINS_EMPTY)
        return nextDelayUs
    }

    companion object {
        /**
         * Minimal START→BURST→GAP→END machine matching WTF-PAD dynamics:
         * nonpadding arms BURST; padding expiry in BURST → GAP; padding in GAP
         * stays in GAP; nonpadding in GAP → BURST; infinity/bins → END.
         */
        fun wtfPadLite(
            burst: CircpadHistogram = CircpadHistogram(
                tokens = intArrayOf(4, 4, 2),
                edgesUs = longArrayOf(50_000, 200_000, 1_000_000),
            ),
            gap: CircpadHistogram = CircpadHistogram(
                tokens = intArrayOf(8, 6, 2),
                edgesUs = longArrayOf(1_000, 10_000, 50_000),
            ),
        ): CircpadMachineSpec {
            fun next(vararg pairs: Pair<Circpad.Event, Int>): IntArray {
                val a = IntArray(CircpadStates.NUM_EVENTS) { CircpadStates.IGNORE }
                for ((e, s) in pairs) a[e.ordinal] = s
                return a
            }
            val start = CircpadStateDef(
                name = "start",
                nextState = next(
                    Circpad.Event.NONPADDING_SENT to CircpadStates.BURST,
                    Circpad.Event.NONPADDING_RECV to CircpadStates.BURST,
                ),
            )
            val burstState = CircpadStateDef(
                name = "burst",
                nextState = next(
                    Circpad.Event.PADDING_SENT to CircpadStates.GAP,
                    Circpad.Event.NONPADDING_SENT to CircpadStates.BURST,
                    Circpad.Event.NONPADDING_RECV to CircpadStates.BURST,
                    Circpad.Event.INFINITY to CircpadStates.END,
                    Circpad.Event.BINS_EMPTY to CircpadStates.END,
                ),
                histogram = burst,
            )
            val gapState = CircpadStateDef(
                name = "gap",
                nextState = next(
                    Circpad.Event.PADDING_SENT to CircpadStates.GAP,
                    Circpad.Event.NONPADDING_SENT to CircpadStates.BURST,
                    Circpad.Event.NONPADDING_RECV to CircpadStates.BURST,
                    Circpad.Event.INFINITY to CircpadStates.END,
                    Circpad.Event.BINS_EMPTY to CircpadStates.END,
                    Circpad.Event.LENGTH_COUNT to CircpadStates.END,
                ),
                histogram = gap,
            )
            return CircpadMachineSpec(
                name = "wtf_pad_lite",
                states = listOf(start, burstState, gapState),
            )
        }
    }
}
