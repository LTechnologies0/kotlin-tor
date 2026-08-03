package org.kotlintor.circuit

/**
 * Circuit padding FSM primitives from C Tor `circuitpadding.h` (prop302 / WTF-PAD).
 *
 * See [CircpadHistogram] (token bins) and [CircpadStateMachine] (START/BURST/GAP).
 */
object Circpad {
    /** Microseconds per second (`CIRCPAD_DELAY_UNITS_PER_SECOND`). */
    const val DELAY_UNITS_PER_SECOND: Long = 1_000_000L
    const val DELAY_INFINITE: Long = 0xFFFF_FFFFL // UINT32_MAX

    enum class Event {
        NONPADDING_RECV,
        NONPADDING_SENT,
        PADDING_SENT,
        PADDING_RECV,
        INFINITY,
        BINS_EMPTY,
        LENGTH_COUNT,
    }

    enum class Decision { UNCHANGED, CHANGED }

    /** Bitfield `circpad_circuit_state_t`. */
    object CircState {
        const val BUILDING: Int = 1 shl 0
        const val OPENED: Int = 1 shl 1
        const val NO_STREAMS: Int = 1 shl 2
        const val STREAMS: Int = 1 shl 3
        const val HAS_RELAY_EARLY: Int = 1 shl 4
        const val HAS_NO_RELAY_EARLY: Int = 1 shl 5
        const val ALL: Int =
            BUILDING or OPENED or STREAMS or NO_STREAMS or HAS_RELAY_EARLY or HAS_NO_RELAY_EARLY
    }

    data class MachineRuntime(
        var stateIndex: Int = 0,
        var paddingSent: Int = 0,
        var paddingTarget: Int = 0,
        var armed: Boolean = false,
        var nextDelayUs: Long = DELAY_INFINITE,
    )

    fun matchesStateMask(mask: Int, flags: Int): Boolean {
        if (mask == 0) return true
        // C Tor: each set bit in mask must match corresponding circuit flag.
        // Simplified: require (flags & mask) == mask for positive conditions.
        return (flags and mask) == mask || mask == CircState.ALL
    }

    fun sampleDelayUs(lowUs: Long, highUs: Long): Long {
        if (highUs <= lowUs) return lowUs
        val span = (highUs - lowUs).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        return lowUs + org.kotlintor.util.SecureRandomSource.nextInt(span + 1)
    }
}

/**
 * Event-driven padding controller wrapping a [CircuitPaddingMachines.Spec].
 */
class CircpadMachineController(
    private val spec: CircuitPaddingMachines.Spec,
    private val applyStateMask: Int = Circpad.CircState.OPENED,
    private val sendDrop: suspend () -> Unit,
    private val hopCount: Int = 3,
    private val purposeMask: Int = CircpadMachineConditions.PURPOSE_ALL,
    private val vanguardsEnabled: Boolean = false,
    private val reducedPadding: Boolean = false,
) {
    val runtime = Circpad.MachineRuntime()

    fun onEvent(event: Circpad.Event, circFlags: Int = Circpad.CircState.OPENED): Circpad.Decision {
        if (!spec.conditions.mayApply(
                hopCount = hopCount,
                circFlags = circFlags,
                purposeMask = purposeMask,
                vanguardsEnabled = vanguardsEnabled,
                reducedPadding = reducedPadding,
            )
        ) {
            return Circpad.Decision.UNCHANGED
        }
        if (!Circpad.matchesStateMask(applyStateMask, circFlags) &&
            applyStateMask != Circpad.CircState.ALL
        ) {
            return Circpad.Decision.UNCHANGED
        }
        when (event) {
            Circpad.Event.NONPADDING_SENT -> {
                // Client intro: INTRODUCE1 is non-padding sent → arm burst.
                if (spec.kind == CircuitPaddingMachines.Kind.CLIENT_INTRO && !runtime.armed) {
                    runtime.armed = true
                    runtime.paddingTarget = CircuitPaddingMachines.samplePaddingCount(spec)
                    runtime.nextDelayUs = Circpad.sampleDelayUs(0, 100_000)
                    return Circpad.Decision.CHANGED
                }
            }
            Circpad.Event.PADDING_SENT -> {
                runtime.paddingSent++
                if (runtime.paddingSent >= runtime.paddingTarget) {
                    runtime.nextDelayUs = Circpad.DELAY_INFINITE
                    return Circpad.Decision.CHANGED
                }
            }
            Circpad.Event.LENGTH_COUNT, Circpad.Event.BINS_EMPTY -> {
                runtime.nextDelayUs = Circpad.DELAY_INFINITE
                return Circpad.Decision.CHANGED
            }
            else -> Unit
        }
        return Circpad.Decision.UNCHANGED
    }

    suspend fun flushIfDue(nowUs: Long = System.nanoTime() / 1000) {
        if (!runtime.armed) return
        if (runtime.nextDelayUs == Circpad.DELAY_INFINITE) return
        if (runtime.paddingSent >= runtime.paddingTarget) return
        sendDrop()
        onEvent(Circpad.Event.PADDING_SENT)
        if (runtime.paddingSent < runtime.paddingTarget) {
            runtime.nextDelayUs = Circpad.sampleDelayUs(0, 50_000)
        }
    }
}
