package org.kotlintor.trunnel

import org.kotlintor.circuit.CircuitExtensions

/**
 * CREATE/EXTEND extension trunnel (C Tor `extension.c`).
 *
 * Inventory: `L1:trunnel/extension.c`
 */
object Extension {
    fun cgoRequest(): CircuitExtensions.Ext = CircuitExtensions.cgoSubprotoRequest()
}
