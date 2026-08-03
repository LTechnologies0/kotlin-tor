package org.kotlintor.circuit

/**
 * Machine apply/keep conditions (C Tor `circpad_machine_conditions_t`).
 *
 * A circuit must satisfy every positive field before the machine is applied;
 * [keepStateMask] / [keepPurposeMask] decide whether an already-running machine
 * stays attached when circuit state/purpose changes.
 */
data class CircpadMachineConditions(
    val minHops: Int = 0,
    val requiresVanguards: Boolean = false,
    val reducedPaddingOk: Boolean = true,
    val applyStateMask: Int = Circpad.CircState.ALL,
    val applyPurposeMask: Int = PURPOSE_ALL,
    val keepStateMask: Int = Circpad.CircState.ALL,
    val keepPurposeMask: Int = PURPOSE_ALL,
) {
    fun mayApply(
        hopCount: Int,
        circFlags: Int,
        purposeMask: Int,
        vanguardsEnabled: Boolean,
        reducedPadding: Boolean,
    ): Boolean {
        if (hopCount < minHops) return false
        if (requiresVanguards && !vanguardsEnabled) return false
        if (reducedPadding && !reducedPaddingOk) return false
        if (!Circpad.matchesStateMask(applyStateMask, circFlags)) return false
        if (applyPurposeMask != PURPOSE_ALL && (purposeMask and applyPurposeMask) == 0) return false
        return true
    }

    fun mayKeep(circFlags: Int, purposeMask: Int): Boolean {
        // C Tor: keep if (flags & keep_mask) != 0 when keep_mask != ALL/0 semantics.
        if (keepStateMask != Circpad.CircState.ALL && keepStateMask != 0) {
            if ((circFlags and keepStateMask) == 0) return false
        }
        if (keepPurposeMask != PURPOSE_ALL && (purposeMask and keepPurposeMask) == 0) return false
        return true
    }

    companion object {
        const val PURPOSE_ALL: Int = -1 // 0xFFFFFFFF

        /** Intro hide machines: open circuits, ≥2 hops, reduced padding allowed. */
        fun introClient(): CircpadMachineConditions =
            CircpadMachineConditions(
                minHops = 2,
                reducedPaddingOk = true,
                applyStateMask = Circpad.CircState.OPENED or Circpad.CircState.NO_STREAMS,
            )

        fun rendClient(): CircpadMachineConditions =
            CircpadMachineConditions(
                minHops = 2,
                reducedPaddingOk = true,
                applyStateMask = Circpad.CircState.OPENED,
            )

        fun relaySide(): CircpadMachineConditions =
            CircpadMachineConditions(
                minHops = 1,
                reducedPaddingOk = true,
                applyStateMask = Circpad.CircState.OPENED,
            )
    }
}

/**
 * Token removal when the exact delay bin is empty (C Tor `circpad_removal_t`).
 */
enum class CircpadTokenRemoval {
    NONE,
    HIGHER,
    LOWER,
    CLOSEST,
    CLOSEST_USEC,
    EXACT,
}
