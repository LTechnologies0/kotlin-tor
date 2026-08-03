package org.kotlintor.cell

/**
 * Circuit / stream / OR-connection end reasons (C Tor `reasons.c`).
 *
 * Numeric codes match tor-spec / control-spec.
 */
object Reasons {
    // Circuit DESTROY / TRUNCATED
    const val CIRC_NONE: Int = 0
    const val CIRC_PROTOCOL: Int = 1
    const val CIRC_INTERNAL: Int = 2
    const val CIRC_REQUESTED: Int = 3
    const val CIRC_HIBERNATING: Int = 4
    const val CIRC_RESOURCELIMIT: Int = 5
    const val CIRC_CONNECTFAILED: Int = 6
    const val CIRC_OR_IDENTITY: Int = 7
    const val CIRC_CHANNEL_CLOSED: Int = 8
    const val CIRC_FINISHED: Int = 9
    const val CIRC_TIMEOUT: Int = 10
    const val CIRC_DESTROYED: Int = 11
    const val CIRC_NOSUCHSERVICE: Int = 12

    // Stream END
    const val STREAM_MISC: Int = 1
    const val STREAM_RESOLVEFAILED: Int = 2
    const val STREAM_CONNECTREFUSED: Int = 3
    const val STREAM_EXITPOLICY: Int = 4
    const val STREAM_DESTROY: Int = 5
    const val STREAM_DONE: Int = 6
    const val STREAM_TIMEOUT: Int = 7
    const val STREAM_NOROUTE: Int = 8
    const val STREAM_HIBERNATING: Int = 9
    const val STREAM_INTERNAL: Int = 10
    const val STREAM_RESOURCELIMIT: Int = 11
    const val STREAM_CONNRESET: Int = 12
    const val STREAM_TORPROTOCOL: Int = 13
    const val STREAM_NOTDIRECTORY: Int = 14

    fun circuitEndToControl(reason: Int): String = when (reason) {
        CIRC_NONE -> "NONE"
        CIRC_PROTOCOL -> "PROTOCOL"
        CIRC_INTERNAL -> "INTERNAL"
        CIRC_REQUESTED -> "REQUESTED"
        CIRC_HIBERNATING -> "HIBERNATING"
        CIRC_RESOURCELIMIT -> "RESOURCELIMIT"
        CIRC_CONNECTFAILED -> "CONNECTFAILED"
        CIRC_OR_IDENTITY -> "OR_IDENTITY"
        CIRC_CHANNEL_CLOSED -> "CHANNEL_CLOSED"
        CIRC_FINISHED -> "FINISHED"
        CIRC_TIMEOUT -> "TIMEOUT"
        CIRC_DESTROYED -> "DESTROYED"
        CIRC_NOSUCHSERVICE -> "NOSUCHSERVICE"
        else -> "UNKNOWN_$reason"
    }

    fun streamEndToControl(reason: Int): String = when (reason) {
        STREAM_MISC -> "MISC"
        STREAM_RESOLVEFAILED -> "RESOLVEFAILED"
        STREAM_CONNECTREFUSED -> "CONNECTREFUSED"
        STREAM_EXITPOLICY -> "EXITPOLICY"
        STREAM_DESTROY -> "DESTROY"
        STREAM_DONE -> "DONE"
        STREAM_TIMEOUT -> "TIMEOUT"
        STREAM_NOROUTE -> "NOROUTE"
        STREAM_HIBERNATING -> "HIBERNATING"
        STREAM_INTERNAL -> "INTERNAL"
        STREAM_RESOURCELIMIT -> "RESOURCELIMIT"
        STREAM_CONNRESET -> "CONNRESET"
        STREAM_TORPROTOCOL -> "TORPROTOCOL"
        STREAM_NOTDIRECTORY -> "NOTDIRECTORY"
        else -> "UNKNOWN_$reason"
    }

    fun streamEndToString(reason: Int): String = when (reason) {
        STREAM_MISC -> "misc error"
        STREAM_RESOLVEFAILED -> "resolve failed"
        STREAM_CONNECTREFUSED -> "connect refused"
        STREAM_EXITPOLICY -> "exit policy rejected"
        STREAM_DESTROY -> "destroyed"
        STREAM_DONE -> "done"
        STREAM_TIMEOUT -> "timeout"
        STREAM_NOROUTE -> "no route"
        STREAM_HIBERNATING -> "hibernating"
        STREAM_INTERNAL -> "internal error"
        STREAM_RESOURCELIMIT -> "resource limit"
        STREAM_CONNRESET -> "connection reset"
        STREAM_TORPROTOCOL -> "tor protocol violation"
        STREAM_NOTDIRECTORY -> "not a directory"
        else -> "unknown reason $reason"
    }

    fun orconnEndToControl(reason: Int): String = when (reason) {
        0 -> "DONE"
        1 -> "MISC"
        2 -> "IDENTITY"
        3 -> "CONNECTREFUSED"
        4 -> "NOROUTE"
        5 -> "IOERROR"
        6 -> "RESOURCELIMIT"
        7 -> "PT_MISSING"
        8 -> "TLS_ERROR"
        else -> "UNKNOWN_$reason"
    }

    fun streamEndToSocks5(reason: Int): Int = when (reason) {
        STREAM_DONE -> 0x00
        STREAM_NOROUTE, STREAM_RESOLVEFAILED -> 0x04 // host unreachable
        STREAM_CONNECTREFUSED -> 0x05
        STREAM_TIMEOUT -> 0x06
        STREAM_EXITPOLICY -> 0x02 // not allowed
        STREAM_HIBERNATING, STREAM_RESOURCELIMIT -> 0x03
        else -> 0x01 // general failure
    }
}

/**
 * Circuit purpose tags (C Tor `circuit_purpose` subset).
 */
enum class CircuitPurpose(val wireName: String) {
    GENERAL("GENERAL"),
    DIR_FETCH("DIR_FETCH"),
    DIR_UPLOAD("DIR_UPLOAD"),
    HS_CLIENT_INTRO("HS_CLIENT_INTRO"),
    HS_CLIENT_REND("HS_CLIENT_REND"),
    HS_SERVICE_INTRO("HS_SERVICE_INTRO"),
    HS_SERVICE_REND("HS_SERVICE_REND"),
    TESTING("TESTING"),
    MEASURE_TIMEOUT("MEASURE_TIMEOUT"),
    CONTROLLER("CONTROLLER"),
}
