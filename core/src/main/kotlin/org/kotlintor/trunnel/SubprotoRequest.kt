package org.kotlintor.trunnel

/**
 * Subprotocol request trunnel (C Tor `subproto_request.c`).
 *
 * Inventory: `L1:trunnel/subproto_request.c`
 *
 * Codec: [SubprotoRequestTrunnel].
 */
object SubprotoRequest {
    fun encode(entries: Map<String, String>): ByteArray = SubprotoRequestTrunnel.encode(entries)
    fun parse(payload: ByteArray): Map<String, String> = SubprotoRequestTrunnel.parse(payload)
}
