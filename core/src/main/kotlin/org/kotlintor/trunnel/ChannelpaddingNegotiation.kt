package org.kotlintor.trunnel

/**
 * Channel padding negotiation trunnel (C Tor `channelpadding_negotiation.c`).
 *
 * Inventory: `L1:trunnel/channelpadding_negotiation.c`
 */
object ChannelpaddingNegotiation {
    const val COMMAND: String = "PADDING_NEGOTIATE"

    fun known(): Boolean = true
}
