package org.kotlintor.hs

import org.kotlintor.dir.RouterStatus
import org.kotlintor.util.concat
import org.kotlintor.util.toHex
import org.kotlintor.util.u16be
import java.net.InetAddress

data class ParsedLinkSpecs(
    val ipv4: ByteArray?,
    val port: Int?,
    val legacyId: ByteArray?,
    val ed25519Id: ByteArray?,
    val rawEntries: List<ByteArray>,
)

object LinkSpecifiers {
    /** Pack nspec + link-specifiers for an introduction-point line. */
    fun packForRelay(relay: RouterStatus, ed25519Identity: ByteArray? = relay.ed25519Identity): ByteArray {
        val entries = ArrayList<ByteArray>()
        val ipv4 = InetAddress.getByName(relay.ip).address
        require(ipv4.size == 4) { "intro point needs IPv4" }
        entries += concat(byteArrayOf(0, 6), ipv4, u16be(relay.orPort))
        entries += concat(byteArrayOf(2, 20), relay.identity)
        if (ed25519Identity != null) {
            require(ed25519Identity.size == 32)
            entries += concat(byteArrayOf(3, 32), ed25519Identity)
        }
        return concat(byteArrayOf(entries.size.toByte()), *entries.toTypedArray())
    }

    fun parsePacked(blob: ByteArray): ParsedLinkSpecs {
        require(blob.isNotEmpty()) { "empty link specifier list" }
        var i = 0
        val nspec = blob[i].toInt() and 0xff
        i++
        var ipv4: ByteArray? = null
        var port: Int? = null
        var legacy: ByteArray? = null
        var ed: ByteArray? = null
        val entries = ArrayList<ByteArray>(nspec)
        repeat(nspec) {
            require(i + 2 <= blob.size) { "truncated link specifier header" }
            val type = blob[i].toInt() and 0xff
            val len = blob[i + 1].toInt() and 0xff
            require(i + 2 + len <= blob.size) { "truncated link specifier body" }
            val entry = blob.copyOfRange(i, i + 2 + len)
            entries += entry
            val data = blob.copyOfRange(i + 2, i + 2 + len)
            when (type) {
                0 -> { // IPv4
                    require(data.size == 6)
                    ipv4 = data.copyOfRange(0, 4)
                    port = ((data[4].toInt() and 0xff) shl 8) or (data[5].toInt() and 0xff)
                }
                2 -> { // legacy identity
                    require(data.size == 20)
                    legacy = data
                }
                3 -> { // ed25519 identity
                    require(data.size == 32)
                    ed = data
                }
            }
            i += 2 + len
        }
        return ParsedLinkSpecs(ipv4, port, legacy, ed, entries)
    }

    fun fingerprintHex(legacyId: ByteArray): String = legacyId.toHex().uppercase()
}
