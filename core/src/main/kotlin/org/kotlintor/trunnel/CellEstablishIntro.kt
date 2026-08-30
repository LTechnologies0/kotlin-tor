package org.kotlintor.trunnel

import org.kotlintor.hs.HsCell

/**
 * ESTABLISH_INTRO cell trunnel (C Tor `cell_establish_intro.c`).
 *
 * Inventory: `L1:trunnel/cell_establish_intro.c`
 */
object CellEstablishIntro {
    const val COMMAND: String = HsCell.ESTABLISH_INTRO
}
