package org.kotlintor.dir

/**
 * Human-readable node descriptions (C Tor `describe.c`).
 *
 * Inventory: `L1:feature/nodelist/describe.c`
 */
object Describe {
    fun node(
        nickname: String?,
        identityHex: String?,
        ipv4: String? = null,
        orPort: Int? = null,
        ed25519Hex: String? = null,
    ): String {
        val id = identityHex?.uppercase()?.take(40)
        val nick = nickname?.takeIf { it.isNotEmpty() } ?: "Unnamed"
        // C Tor describe.c: address without ORPort; ed as full hex/base64 bracket form.
        val addr = ipv4
        return buildString {
            append('$')
            append(id ?: "????????????????????????????????????????")
            append('~')
            append(nick)
            if (!ed25519Hex.isNullOrBlank()) {
                append(" [")
                append(ed25519Hex.lowercase())
                append(']')
            }
            if (addr != null) {
                append(" at ")
                append(addr)
            }
            // orPort retained for callers that pass it but omitted from C Tor string form
            @Suppress("UNUSED_EXPRESSION")
            orPort
        }
    }

    fun routerStatus(rs: RouterStatus): String =
        node(rs.nickname, rs.fingerprintHex, rs.ip, rs.orPort, rs.ed25519Identity?.let {
            it.joinToString("") { b -> "%02x".format(b) }
        })

    /** C Tor `format_node_description`. */
    fun formatNodeDescription(
        nickname: String?,
        identityHex: String?,
        ipv4: String? = null,
        orPort: Int? = null,
    ): String = node(nickname, identityHex, ipv4, orPort)

    /** C Tor `extend_info_describe`. */
    fun extendInfoDescribe(
        identityHex: String?,
        ipv4: String?,
        orPort: Int?,
        nickname: String? = null,
    ): String = node(nickname, identityHex, ipv4, orPort)

    /** C Tor `node_describe`. */
    fun nodeDescribe(rs: RouterStatus): String = routerStatus(rs)
}
