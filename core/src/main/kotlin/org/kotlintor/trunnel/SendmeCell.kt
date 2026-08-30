package org.kotlintor.trunnel

import org.kotlintor.cell.RelayCommand

/**
 * SENDME cell trunnel (C Tor `sendme_cell.c`).
 *
 * Inventory: `L1:trunnel/sendme_cell.c`
 */
object SendmeCell {
    fun command(): RelayCommand = RelayCommand.SENDME
    fun versionByte(v: Int): ByteArray = byteArrayOf(v.toByte())
}
