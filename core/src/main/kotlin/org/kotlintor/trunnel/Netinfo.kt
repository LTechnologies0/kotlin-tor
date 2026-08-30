package org.kotlintor.trunnel

import org.kotlintor.cell.Cell

/**
 * NETINFO trunnel (C Tor `netinfo.c`).
 *
 * Inventory: `L1:trunnel/netinfo.c`
 *
 * Codec: [NetinfoTrunnel].
 */
object Netinfo {
    fun encodeTimestamp(epochSec: Long): ByteArray = NetinfoTrunnel.encodeTimestamp(epochSec)
    fun timestampFromCell(cell: Cell): Long = NetinfoTrunnel.timestampFromCell(cell)
}
