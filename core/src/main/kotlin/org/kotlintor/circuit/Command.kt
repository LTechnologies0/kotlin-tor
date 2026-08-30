package org.kotlintor.circuit

import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.link.ChannelState
import org.kotlintor.link.OrChannel
import org.kotlintor.or.ChannelListener

/**
 * Channel cell command dispatch (C Tor `command.c`).
 *
 * Inventory: `L1:core/or/command.c`
 *
 * Maps link/circuit cell commands to handler categories used by the OR.
 */
object Command {
    enum class Handler {
        PADDING,
        VERSIONS,
        CERTS,
        AUTH_CHALLENGE,
        AUTHENTICATE,
        NETINFO,
        CREATE,
        CREATED,
        RELAY,
        DESTROY,
        VPADDING,
        PADDING_NEGOTIATE,
        UNKNOWN,
    }

    fun classify(cmd: CellCommand): Handler = when (cmd) {
        CellCommand.PADDING -> Handler.PADDING
        CellCommand.VPADDING -> Handler.VPADDING
        CellCommand.VERSIONS -> Handler.VERSIONS
        CellCommand.CERTS -> Handler.CERTS
        CellCommand.AUTH_CHALLENGE -> Handler.AUTH_CHALLENGE
        CellCommand.AUTHENTICATE -> Handler.AUTHENTICATE
        CellCommand.NETINFO -> Handler.NETINFO
        CellCommand.CREATE, CellCommand.CREATE_FAST, CellCommand.CREATE2 -> Handler.CREATE
        CellCommand.CREATED, CellCommand.CREATED_FAST, CellCommand.CREATED2 -> Handler.CREATED
        CellCommand.RELAY, CellCommand.RELAY_EARLY -> Handler.RELAY
        CellCommand.DESTROY -> Handler.DESTROY
        CellCommand.PADDING_NEGOTIATE -> Handler.PADDING_NEGOTIATE
        else -> Handler.UNKNOWN
    }

    fun classify(cell: Cell): Handler = classify(cell.command)

    fun isHandshakeCell(cmd: CellCommand): Boolean =
        classify(cmd) in setOf(
            Handler.VERSIONS,
            Handler.CERTS,
            Handler.AUTH_CHALLENGE,
            Handler.AUTHENTICATE,
            Handler.NETINFO,
        )

    fun requiresCircuit(cmd: CellCommand): Boolean =
        classify(cmd) in setOf(Handler.CREATE, Handler.CREATED, Handler.RELAY, Handler.DESTROY)

    /** C Tor `cell_command_to_string`. */
    fun cellCommandToString(cmd: CellCommand): String = cmd.name.lowercase()

    fun cellCommandToString(id: Int): String =
        CellCommand.fromIdOrNull(id)?.let { cellCommandToString(it) } ?: "unknown"

    /** C Tor `command_process_cell` — classify and accept known handlers. */
    fun commandProcessCell(cell: Cell): Handler = classify(cell)

    /** C Tor `command_setup_channel`. */
    fun commandSetupChannel(chan: OrChannel): OrChannel {
        chan.state = ChannelState.OPENING
        return chan
    }

    /** C Tor `command_setup_listener`. */
    fun commandSetupListener(listener: ChannelListener): ChannelListener = listener
}
