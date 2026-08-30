package org.kotlintor.trunnel

import org.kotlintor.hs.HsCell

/**
 * Rendezvous cell trunnel (C Tor `cell_rendezvous.c`).
 *
 * Inventory: `L1:trunnel/cell_rendezvous.c`
 */
object CellRendezvous {
    const val COMMAND: String = HsCell.RENDEZVOUS1
}
