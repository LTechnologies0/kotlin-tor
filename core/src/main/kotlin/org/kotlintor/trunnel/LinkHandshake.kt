package org.kotlintor.trunnel

/**
 * Link handshake trunnel (C Tor `link_handshake.c`).
 *
 * Inventory: `L1:trunnel/link_handshake.c`
 *
 * Codec: [LinkHandshakeTrunnel].
 */
object LinkHandshake {
    fun versionsPayload(versions: List<Int>): ByteArray = LinkHandshakeTrunnel.versionsPayload(versions)
    fun parseVersions(payload: ByteArray): List<Int> = LinkHandshakeTrunnel.parseVersions(payload)
}
