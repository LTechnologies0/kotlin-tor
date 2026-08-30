package org.kotlintor.trunnel

/**
 * Password-box trunnel (C Tor `pwbox.c`).
 *
 * Inventory: `L1:trunnel/pwbox.c`
 *
 * Codec: [PwBoxTrunnel].
 */
object Pwbox {
    fun supported(): Boolean = PwBoxTrunnel.supported()
}
