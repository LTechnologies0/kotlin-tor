package org.kotlintor.circuit

import org.kotlintor.cell.RelayCell
import org.kotlintor.cell.RelayCommand
import org.kotlintor.util.readU32be
import org.kotlintor.util.u32be

/**
 * Circuit padding negotiation (C Tor `circpad_negotiation.trunnel` /
 * RELAY_COMMAND_PADDING_NEGOTIATE=41 / NEGOTIATED=42).
 *
 * Distinct from link-level [org.kotlintor.link.PaddingNegotiate] (prop254).
 */
object CircpadNegotiate {
    const val COMMAND_STOP: Int = 1
    const val COMMAND_START: Int = 2
    const val RESPONSE_OK: Int = 1
    const val RESPONSE_ERR: Int = 2
    const val MACHINE_CIRC_SETUP: Int = 1
    const val VERSION: Int = 0

    data class Negotiate(
        val version: Int = VERSION,
        val command: Int,
        val machineType: Int,
        val echoRequest: Int = 0,
        val machineCtr: Long = 0,
    )

    data class Negotiated(
        val version: Int = VERSION,
        val command: Int,
        val response: Int,
        val machineType: Int,
        val machineCtr: Long = 0,
    )

    fun encodeNegotiate(n: Negotiate): ByteArray =
        byteArrayOf(
            n.version.toByte(),
            n.command.toByte(),
            n.machineType.toByte(),
            n.echoRequest.toByte(),
        ) + u32be(n.machineCtr)

    fun parseNegotiate(body: ByteArray): Negotiate {
        require(body.size >= 8) { "circpad_negotiate truncated" }
        return Negotiate(
            version = body[0].toInt() and 0xff,
            command = body[1].toInt() and 0xff,
            machineType = body[2].toInt() and 0xff,
            echoRequest = body[3].toInt() and 0xff,
            machineCtr = readU32be(body, 4),
        )
    }

    fun encodeNegotiated(n: Negotiated): ByteArray =
        byteArrayOf(
            n.version.toByte(),
            n.command.toByte(),
            n.response.toByte(),
            n.machineType.toByte(),
        ) + u32be(n.machineCtr)

    fun parseNegotiated(body: ByteArray): Negotiated {
        require(body.size >= 8) { "circpad_negotiated truncated" }
        return Negotiated(
            version = body[0].toInt() and 0xff,
            command = body[1].toInt() and 0xff,
            response = body[2].toInt() and 0xff,
            machineType = body[3].toInt() and 0xff,
            machineCtr = readU32be(body, 4),
        )
    }

    fun startCell(
        machineType: Int = MACHINE_CIRC_SETUP,
        machineCtr: Long = 1,
        echoRequest: Boolean = false,
    ): RelayCell =
        RelayCell.build(
            RelayCommand.PADDING_NEGOTIATE,
            0,
            encodeNegotiate(
                Negotiate(
                    command = COMMAND_START,
                    machineType = machineType,
                    echoRequest = if (echoRequest) 1 else 0,
                    machineCtr = machineCtr,
                ),
            ),
        )

    fun stopCell(machineType: Int = MACHINE_CIRC_SETUP, machineCtr: Long = 0): RelayCell =
        RelayCell.build(
            RelayCommand.PADDING_NEGOTIATE,
            0,
            encodeNegotiate(
                Negotiate(command = COMMAND_STOP, machineType = machineType, machineCtr = machineCtr),
            ),
        )

    fun replyOk(forNegotiate: Negotiate): RelayCell =
        RelayCell.build(
            RelayCommand.PADDING_NEGOTIATED,
            0,
            encodeNegotiated(
                Negotiated(
                    command = forNegotiate.command,
                    response = RESPONSE_OK,
                    machineType = forNegotiate.machineType,
                    machineCtr = forNegotiate.machineCtr,
                ),
            ),
        )

    fun replyErr(forNegotiate: Negotiate): RelayCell =
        RelayCell.build(
            RelayCommand.PADDING_NEGOTIATED,
            0,
            encodeNegotiated(
                Negotiated(
                    command = forNegotiate.command,
                    response = RESPONSE_ERR,
                    machineType = forNegotiate.machineType,
                    machineCtr = forNegotiate.machineCtr,
                ),
            ),
        )
}

/**
 * Origin/middle handler: START arms [CircpadStateMachine]; STOP tears down.
 */
class CircpadNegotiateSession(
    private val machineFactory: () -> CircpadStateMachine = {
        CircpadStateMachine(CircpadStateMachine.wtfPadLite())
    },
    private val knownMachines: Set<Int> = setOf(CircpadNegotiate.MACHINE_CIRC_SETUP),
) {
    var machine: CircpadStateMachine? = null
        private set
    var activeCtr: Long = 0
        private set
    var lastResponse: CircpadNegotiate.Negotiated? = null
        private set

    fun handleNegotiate(body: ByteArray): RelayCell {
        val n = CircpadNegotiate.parseNegotiate(body)
        if (n.version != CircpadNegotiate.VERSION || n.machineType !in knownMachines) {
            val err = CircpadNegotiate.replyErr(n)
            lastResponse = CircpadNegotiate.parseNegotiated(err.data)
            return err
        }
        when (n.command) {
            CircpadNegotiate.COMMAND_START -> {
                machine = machineFactory()
                activeCtr = n.machineCtr
                machine!!.onEvent(Circpad.Event.NONPADDING_SENT)
            }
            CircpadNegotiate.COMMAND_STOP -> {
                if (n.machineCtr == 0L || n.machineCtr == activeCtr) {
                    machine = null
                    activeCtr = 0
                }
            }
            else -> {
                val err = CircpadNegotiate.replyErr(n)
                lastResponse = CircpadNegotiate.parseNegotiated(err.data)
                return err
            }
        }
        val ok = CircpadNegotiate.replyOk(n)
        lastResponse = CircpadNegotiate.parseNegotiated(ok.data)
        return ok
    }

    fun handleNegotiated(body: ByteArray): Boolean {
        val n = CircpadNegotiate.parseNegotiated(body)
        lastResponse = n
        if (n.response != CircpadNegotiate.RESPONSE_OK) {
            machine = null
            return false
        }
        if (n.command == CircpadNegotiate.COMMAND_START && machine == null) {
            machine = machineFactory()
            activeCtr = n.machineCtr
        }
        if (n.command == CircpadNegotiate.COMMAND_STOP) {
            machine = null
            activeCtr = 0
        }
        return true
    }
}
