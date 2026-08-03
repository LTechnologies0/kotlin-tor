package org.kotlintor.circuit

/**
 * CREATE2/CREATED2 handshake extensions (tor-spec §"Sending extensions").
 *
 * | N_EXTENSIONS | 1 |
 * | EXT_FIELD_TYPE | 1 |
 * | EXT_FIELD_LEN | 1 |
 * | EXT_FIELD | LEN |
 */
object CircuitExtensions {
    const val CC_FIELD_REQUEST: Int = 1
    const val CC_FIELD_RESPONSE: Int = 2
    const val SUBPROTO_REQUEST: Int = 3

    /** Numeric protocol_id values from tor-spec subprotocol versioning. */
    object ProtoId {
        const val LINK: Int = 0
        const val LINK_AUTH: Int = 1
        const val RELAY: Int = 2
        const val DIR_CACHE: Int = 3
        const val HS_DIR: Int = 4
        const val HS_INTRO: Int = 5
        const val HS_REND: Int = 6
        const val DESC: Int = 7
        const val MICRODESC: Int = 8
        const val CONS: Int = 9
        const val PADDING: Int = 10
        const val FLOW_CTRL: Int = 11
        const val CONFLUX: Int = 12
    }

    /** Only Relay=6 (RELAY_CRYPT_CGO) is listed for SUBPROTO in current tor-spec. */
    const val RELAY_CRYPT_CGO: Int = 6

    private val PROTO_NAME_TO_ID: Map<String, Int> = mapOf(
        "Link" to ProtoId.LINK,
        "LinkAuth" to ProtoId.LINK_AUTH,
        "Relay" to ProtoId.RELAY,
        "DirCache" to ProtoId.DIR_CACHE,
        "HSDir" to ProtoId.HS_DIR,
        "HSIntro" to ProtoId.HS_INTRO,
        "HSRend" to ProtoId.HS_REND,
        "Desc" to ProtoId.DESC,
        "Microdesc" to ProtoId.MICRODESC,
        "Cons" to ProtoId.CONS,
        "Padding" to ProtoId.PADDING,
        "FlowCtrl" to ProtoId.FLOW_CTRL,
        "Conflux" to ProtoId.CONFLUX,
    )

    private val PROTO_ID_TO_NAME: Map<Int, String> =
        PROTO_NAME_TO_ID.entries.associate { (k, v) -> v to k }

    data class Ext(val type: Int, val body: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Ext && type == other.type && body.contentEquals(other.body)

        override fun hashCode(): Int = 31 * type + body.contentHashCode()
    }

    fun encode(exts: List<Ext>): ByteArray {
        require(exts.size <= 255)
        val out = ArrayList<Byte>(1 + exts.sumOf { 2 + it.body.size })
        out += exts.size.toByte()
        for (e in exts) {
            require(e.type in 0..255 && e.body.size <= 255)
            out += e.type.toByte()
            out += e.body.size.toByte()
            for (b in e.body) out += b
        }
        return out.toByteArray()
    }

    fun decode(msg: ByteArray): List<Ext> {
        if (msg.isEmpty()) return emptyList()
        var i = 0
        val n = msg[i++].toInt() and 0xff
        val out = ArrayList<Ext>(n)
        repeat(n) {
            require(i + 2 <= msg.size) { "truncated extension header" }
            val type = msg[i++].toInt() and 0xff
            val len = msg[i++].toInt() and 0xff
            require(i + len <= msg.size) { "truncated extension body" }
            out += Ext(type, msg.copyOfRange(i, i + len))
            i += len
        }
        return out
    }

    fun ccRequest(): ByteArray = encode(listOf(Ext(CC_FIELD_REQUEST, ByteArray(0))))

    fun ccResponse(sendmeInc: Int): ByteArray {
        require(sendmeInc in 0..255)
        return encode(listOf(Ext(CC_FIELD_RESPONSE, byteArrayOf(sendmeInc.toByte()))))
    }

    fun sendmeIncOrNull(serverMessage: ByteArray): Int? {
        val exts = runCatching { decode(serverMessage) }.getOrNull() ?: return null
        val body = exts.firstOrNull { it.type == CC_FIELD_RESPONSE }?.body ?: return null
        if (body.isEmpty()) return null
        return body[0].toInt() and 0xff
    }

    fun clientRequestedCc(clientMessage: ByteArray): Boolean =
        runCatching { decode(clientMessage) }.getOrNull()
            ?.any { it.type == CC_FIELD_REQUEST } == true

    data class ProtoReq(val name: String, val version: Int) {
        val protocolId: Int
            get() = PROTO_NAME_TO_ID[name]
                ?: error("unknown subprotocol name: $name")
    }

    /**
     * SUBPROTO_REQUEST body (prop346 / tor-spec): concatenated
     * `protocol_id (1) || cap_number (1)` pairs, sorted ascending.
     * Example: Relay=6 → `[0x02, 0x06]`.
     */
    fun subprotoRequestExt(reqs: List<ProtoReq>): Ext {
        val sorted = reqs.sortedWith(compareBy({ it.protocolId }, { it.version }))
        val body = ByteArray(sorted.size * 2)
        var i = 0
        for (r in sorted) {
            require(r.version in 0..255)
            body[i++] = r.protocolId.toByte()
            body[i++] = r.version.toByte()
        }
        return Ext(SUBPROTO_REQUEST, body)
    }

    /** Convenience: SUBPROTO requesting Relay=6 (CGO). */
    fun cgoSubprotoRequest(): Ext =
        subprotoRequestExt(listOf(ProtoReq("Relay", RELAY_CRYPT_CGO)))

    fun subprotoRequest(reqs: List<ProtoReq>): ByteArray =
        encode(listOf(subprotoRequestExt(reqs)))

    fun decodeSubprotoRequest(body: ByteArray): List<ProtoReq> {
        if (body.isEmpty()) return emptyList()
        // Legacy ASCII (pre-fix): "Name=Ver\0Name=Ver"
        if (body.any { it == '='.code.toByte() }) {
            return body.toString(Charsets.US_ASCII).split('\u0000').mapNotNull { part ->
                val t = part.trim()
                if (t.isEmpty()) return@mapNotNull null
                val name = t.substringBefore('=')
                val ver = t.substringAfter('=', "").toIntOrNull() ?: return@mapNotNull null
                ProtoReq(name, ver)
            }
        }
        // Binary (tor-spec / prop346): protocol_id || cap_number pairs
        if (body.size % 2 != 0) return emptyList()
        val out = ArrayList<ProtoReq>(body.size / 2)
        var i = 0
        while (i < body.size) {
            val id = body[i].toInt() and 0xff
            val cap = body[i + 1].toInt() and 0xff
            i += 2
            val name = PROTO_ID_TO_NAME[id] ?: continue
            out += ProtoReq(name, cap)
        }
        return out
    }

    fun clientRequestedCgo(clientMessage: ByteArray): Boolean {
        val exts = runCatching { decode(clientMessage) }.getOrNull() ?: return false
        return exts.any { e ->
            e.type == SUBPROTO_REQUEST &&
                decodeSubprotoRequest(e.body).any { it.name == "Relay" && it.version >= RELAY_CRYPT_CGO }
        }
    }

    /** True if server extensions acknowledge Relay=6 (CGO). Handshake success alone also implies accept. */
    fun serverAcceptedCgo(serverMessage: ByteArray): Boolean {
        val exts = runCatching { decode(serverMessage) }.getOrNull() ?: return false
        for (e in exts) {
            if (e.type == SUBPROTO_REQUEST || e.type == 4 /* SUBPROTO_RESPONSE provisional */) {
                if (decodeSubprotoRequest(e.body).any { it.name == "Relay" && it.version >= RELAY_CRYPT_CGO }) {
                    return true
                }
            }
        }
        return false
    }
}
