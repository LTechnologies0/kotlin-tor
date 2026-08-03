package org.kotlintor.cell

enum class CellCommand(val id: Int, val variable: Boolean = false) {
    PADDING(0),
    CREATE(1),
    CREATED(2),
    RELAY(3),
    DESTROY(4),
    CREATE_FAST(5),
    CREATED_FAST(6),
    VERSIONS(7, variable = true),
    NETINFO(8),
    RELAY_EARLY(9),
    CREATE2(10),
    CREATED2(11),
    PADDING_NEGOTIATE(12),
    VPADDING(128, variable = true),
    CERTS(129, variable = true),
    AUTH_CHALLENGE(130, variable = true),
    AUTHENTICATE(131, variable = true),
    AUTHORIZE(132, variable = true),
    ;

    companion object {
        private val byId = entries.associateBy { it.id }
        fun fromId(id: Int): CellCommand =
            byId[id] ?: error("unknown cell command $id")

        fun fromIdOrNull(id: Int): CellCommand? = byId[id]
    }
}

enum class RelayCommand(val id: Int) {
    BEGIN(1),
    DATA(2),
    END(3),
    CONNECTED(4),
    SENDME(5),
    EXTEND(6),
    EXTENDED(7),
    TRUNCATE(8),
    TRUNCATED(9),
    DROP(10),
    RESOLVE(11),
    RESOLVED(12),
    BEGIN_DIR(13),
    EXTEND2(14),
    EXTENDED2(15),
    CONFLUX_LINK(19),
    CONFLUX_LINKED(20),
    CONFLUX_LINKED_ACK(21),
    CONFLUX_SWITCH(22),
    ESTABLISH_INTRO(32),
    ESTABLISH_RENDEZVOUS(33),
    INTRODUCE1(34),
    INTRODUCE2(35),
    RENDEZVOUS1(36),
    RENDEZVOUS2(37),
    INTRO_ESTABLISHED(38),
    RENDEZVOUS_ESTABLISHED(39),
    INTRODUCE_ACK(40),
    PADDING_NEGOTIATE(41),
    PADDING_NEGOTIATED(42),
    XOFF(43),
    XON(44),
    ;

    /**
     * C Tor `relay_cmd_expects_streamid_in_v1` (relay_msg.h): only these commands
     * carry a stream ID in RELAY_CELL_FORMAT_V1 (CGO).
     */
    fun expectsStreamIdInV1(): Boolean =
        when (this) {
            BEGIN, BEGIN_DIR, CONNECTED, DATA, END, RESOLVE, RESOLVED, XOFF, XON -> true
            else -> false
        }

    companion object {
        private val byId = entries.associateBy { it.id }
        fun fromId(id: Int): RelayCommand =
            byId[id] ?: error("unknown relay command $id")
    }
}
