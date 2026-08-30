package org.kotlintor.trunnel

import org.kotlintor.cell.RelayCommand

/**
 * Flow-control cell trunnel (C Tor `flow_control_cells.c`).
 *
 * Inventory: `L1:trunnel/flow_control_cells.c`
 */
object FlowControlCells {
    fun xonCommand(): RelayCommand = RelayCommand.XON
    fun xoffCommand(): RelayCommand = RelayCommand.XOFF
    fun known(): Set<RelayCommand> = setOf(RelayCommand.XON, RelayCommand.XOFF, RelayCommand.SENDME)
}
