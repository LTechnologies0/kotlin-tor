package org.kotlintor.net

/**
 * HTTP CONNECT proto helpers (C Tor `proto_http.c`).
 *
 * Inventory: `L1:core/proto/proto_http.c`
 *
 * Implementation: [HttpConnectCodec].
 */
object ProtoHttp {
    fun parseConnect(raw: ByteArray): HttpConnectCodec.Request? =
        HttpConnectCodec.parseRequest(raw)

    fun encodeResponse(code: Int, reason: String): ByteArray =
        HttpConnectCodec.encodeResponse(code, reason)

    fun connectionEstablished(): ByteArray = HttpConnectCodec.connectionEstablished()

    fun isConnectMethod(raw: ByteArray): Boolean {
        val s = raw.decodeToString(0, minOf(raw.size, 16))
        return s.startsWith("CONNECT ", ignoreCase = true)
    }
}
