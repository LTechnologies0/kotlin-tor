package org.kotlintor.trunnel

import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.util.readU16be
import org.kotlintor.util.u16be
import org.kotlintor.util.u32be

/**
 * Shared trunnel helper codecs used by naming primaries in this package.
 */
object LinkHandshakeTrunnel {
    fun versionsPayload(versions: List<Int>): ByteArray =
        versions.fold(ByteArray(0)) { acc, v -> acc + u16be(v) }

    fun parseVersions(payload: ByteArray): List<Int> {
        val out = ArrayList<Int>()
        var i = 0
        while (i + 2 <= payload.size) {
            out += readU16be(payload, i)
            i += 2
        }
        return out
    }
}

object NetinfoTrunnel {
    fun encodeTimestamp(epochSec: Long): ByteArray = u32be(epochSec)

    fun timestampFromCell(cell: Cell): Long {
        require(cell.command == CellCommand.NETINFO)
        require(cell.payload.size >= 4)
        return ((cell.payload[0].toLong() and 0xff) shl 24) or
            ((cell.payload[1].toLong() and 0xff) shl 16) or
            ((cell.payload[2].toLong() and 0xff) shl 8) or
            (cell.payload[3].toLong() and 0xff)
    }
}

object SubprotoRequestTrunnel {
    /** Encode a simple name=version list for testing / future CREATE. */
    fun encode(entries: Map<String, String>): ByteArray {
        val s = entries.entries.joinToString(" ") { "${it.key}=${it.value}" }
        return s.toByteArray(Charsets.US_ASCII)
    }

    fun parse(payload: ByteArray): Map<String, String> {
        val text = payload.toString(Charsets.US_ASCII).trim()
        if (text.isEmpty()) return emptyMap()
        return text.split(' ').mapNotNull { tok ->
            val eq = tok.indexOf('=')
            if (eq <= 0) null else tok.substring(0, eq) to tok.substring(eq + 1)
        }.toMap()
    }
}

/** Password-box trunnel unit — not used on JVM hot path. */
object PwBoxTrunnel {
    fun supported(): Boolean = false
}
