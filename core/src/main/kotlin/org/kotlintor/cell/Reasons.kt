package org.kotlintor.cell

/**
 * Circuit / stream / OR-connection end reasons (C Tor `reasons.c` + `or.h`).
 *
 * Inventory: `L1:core/or/reasons.c` — control strings, SOCKS5/HTTP CONNECT
 * mappings, errno → reason tables.
 */
object Reasons {
    // —— Circuit DESTROY / TRUNCATED (END_CIRC_REASON_*) ——
    const val CIRC_NONE: Int = 0
    /** Alias for [CIRC_TORPROTOCOL] (C Tor `END_CIRC_REASON_TORPROTOCOL`). */
    const val CIRC_PROTOCOL: Int = 1
    const val CIRC_TORPROTOCOL: Int = 1
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
    /** Local-only (not on wire). */
    const val CIRC_AT_ORIGIN: Int = -1
    const val CIRC_NOPATH: Int = -2
    const val CIRC_MEASUREMENT_EXPIRED: Int = -3
    const val CIRC_IP_NOW_REDUNDANT: Int = -4
    const val CIRC_REASON_FLAG_REMOTE: Int = 512

    // —— Stream END (END_STREAM_REASON_*) ——
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
    // Local / control-only (not sent on RELAY_END wire)
    const val STREAM_CANT_ATTACH: Int = 257
    const val STREAM_NET_UNREACHABLE: Int = 258
    const val STREAM_SOCKSPROTOCOL: Int = 259
    const val STREAM_CANT_FETCH_ORIG_DEST: Int = 260
    const val STREAM_INVALID_NATD_DEST: Int = 261
    const val STREAM_PRIVATE_ADDR: Int = 262
    const val STREAM_HTTPPROTOCOL: Int = 263
    const val STREAM_ENTRYPOLICY: Int = 264
    const val STREAM_REASON_MASK: Int = 511
    const val STREAM_FLAG_REMOTE: Int = 512
    const val STREAM_FLAG_ALREADY_SENT_CLOSED: Int = 1024
    const val STREAM_FLAG_ALREADY_SOCKS_REPLIED: Int = 2048

    // —— ORConn (END_OR_CONN_REASON_*) ——
    const val ORCONN_DONE: Int = 1
    const val ORCONN_REFUSED: Int = 2
    const val ORCONN_IDENTITY: Int = 3
    const val ORCONN_CONNRESET: Int = 4
    const val ORCONN_TIMEOUT: Int = 5
    const val ORCONN_NO_ROUTE: Int = 6
    const val ORCONN_IO_ERROR: Int = 7
    const val ORCONN_RESOURCE_LIMIT: Int = 8
    const val ORCONN_PT_MISSING: Int = 9
    const val ORCONN_TLS_ERROR: Int = 10
    const val ORCONN_MISC: Int = 11

    // TOR_TLS_* error codes (subset used by tls_error_to_orconn_end_reason)
    const val TOR_TLS_ERROR_MISC: Int = -1
    const val TOR_TLS_ERROR_IO: Int = -2
    const val TOR_TLS_ERROR_CONNREFUSED: Int = -3
    const val TOR_TLS_ERROR_CONNRESET: Int = -4
    const val TOR_TLS_ERROR_NO_ROUTE: Int = -5
    const val TOR_TLS_ERROR_TIMEOUT: Int = -6
    const val TOR_TLS_CLOSE: Int = -7
    const val TOR_TLS_WANTREAD: Int = -8
    const val TOR_TLS_WANTWRITE: Int = -9
    const val TOR_TLS_DONE: Int = -10

    // SOCKS5 reply status (RFC 1928)
    const val SOCKS5_SUCCEEDED: Int = 0x00
    const val SOCKS5_GENERAL_ERROR: Int = 0x01
    const val SOCKS5_NOT_ALLOWED: Int = 0x02
    const val SOCKS5_NET_UNREACHABLE: Int = 0x03
    const val SOCKS5_HOST_UNREACHABLE: Int = 0x04
    const val SOCKS5_CONNECTION_REFUSED: Int = 0x05
    const val SOCKS5_TTL_EXPIRED: Int = 0x06

    /** Linux errno constants used by errno_*_reason tables. */
    object Errno {
        const val EPERM: Int = 1
        const val ENOENT: Int = 2
        const val EACCES: Int = 13
        const val EFAULT: Int = 14
        const val EINVAL: Int = 22
        const val ENFILE: Int = 23
        const val EMFILE: Int = 24
        const val EPIPE: Int = 32
        const val EAGAIN: Int = 11
        const val ENOMEM: Int = 12
        const val EBADF: Int = 9
        const val ENOTSOCK: Int = 88
        const val EDESTADDRREQ: Int = 89
        const val EMSGSIZE: Int = 90
        const val EPROTOTYPE: Int = 91
        const val ENOPROTOOPT: Int = 92
        const val EPROTONOSUPPORT: Int = 93
        const val ESOCKTNOSUPPORT: Int = 94
        const val EOPNOTSUPP: Int = 95
        const val EPFNOSUPPORT: Int = 96
        const val EAFNOSUPPORT: Int = 97
        const val EADDRINUSE: Int = 98
        const val EADDRNOTAVAIL: Int = 99
        const val ENETDOWN: Int = 100
        const val ENETUNREACH: Int = 101
        const val ENETRESET: Int = 102
        const val ECONNABORTED: Int = 103
        const val ECONNRESET: Int = 104
        const val ENOBUFS: Int = 105
        const val EISCONN: Int = 106
        const val ENOTCONN: Int = 107
        const val ETIMEDOUT: Int = 110
        const val ECONNREFUSED: Int = 111
        const val EHOSTDOWN: Int = 112
        const val EHOSTUNREACH: Int = 113
    }

    /**
     * CIRCUIT event reason string (C Tor `circuit_end_reason_to_control_string`).
     * Returns null for unrecognized codes (C returns NULL).
     */
    fun circuitEndToControl(reason: Int): String? {
        var r = reason
        if (r >= 0 && (r and CIRC_REASON_FLAG_REMOTE) != 0) {
            r = r and CIRC_REASON_FLAG_REMOTE.inv()
        }
        return when (r) {
            CIRC_AT_ORIGIN -> "ORIGIN"
            CIRC_NONE -> "NONE"
            CIRC_TORPROTOCOL -> "TORPROTOCOL"
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
            CIRC_NOPATH -> "NOPATH"
            CIRC_NOSUCHSERVICE -> "NOSUCHSERVICE"
            CIRC_MEASUREMENT_EXPIRED -> "MEASUREMENT_EXPIRED"
            CIRC_IP_NOW_REDUNDANT -> "IP_NOW_REDUNDANT"
            else -> null
        }
    }

    /** C Tor `circuit_end_reason_to_control_string`. */
    fun circuitEndReasonToControlString(reason: Int): String? = circuitEndToControl(reason)

    /** Non-null control string; unknown → `UNKNOWN_$reason` for UI/logging. */
    fun circuitEndToControlOrUnknown(reason: Int): String =
        circuitEndToControl(reason) ?: "UNKNOWN_$reason"

    fun streamEndToControl(reason: Int): String? {
        val r = reason and STREAM_REASON_MASK
        return when (r) {
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
            STREAM_CANT_ATTACH -> "CANT_ATTACH"
            STREAM_NET_UNREACHABLE -> "NET_UNREACHABLE"
            STREAM_SOCKSPROTOCOL -> "SOCKS_PROTOCOL"
            STREAM_HTTPPROTOCOL -> "HTTP_PROTOCOL"
            STREAM_PRIVATE_ADDR -> "PRIVATE_ADDR"
            STREAM_ENTRYPOLICY -> "ENTRYPOLICY"
            else -> null
        }
    }

    fun streamEndToControlOrUnknown(reason: Int): String =
        streamEndToControl(reason) ?: "UNKNOWN_$reason"

    /** C Tor `stream_end_reason_to_control_string`. */
    fun streamEndReasonToControlString(reason: Int): String? = streamEndToControl(reason)

    /** C Tor `stream_end_reason_to_string` (log wording). */
    fun streamEndToString(reason: Int): String = when (reason) {
        -1 -> "MALFORMED"
        STREAM_MISC -> "misc error"
        STREAM_RESOLVEFAILED -> "resolve failed"
        STREAM_CONNECTREFUSED -> "connection refused"
        STREAM_EXITPOLICY -> "exit policy failed"
        STREAM_DESTROY -> "destroyed"
        STREAM_DONE -> "closed normally"
        STREAM_TIMEOUT -> "gave up (timeout)"
        STREAM_NOROUTE -> "no route to host"
        STREAM_HIBERNATING -> "server is hibernating"
        STREAM_INTERNAL -> "internal error at server"
        STREAM_RESOURCELIMIT -> "server out of resources"
        STREAM_CONNRESET -> "connection reset"
        STREAM_TORPROTOCOL -> "Tor protocol error"
        STREAM_NOTDIRECTORY -> "not a directory"
        else -> "unknown"
    }

    /**
     * C Tor `stream_end_reason_to_socks5_response`.
     * Reason 0 → succeeded; DONE before SOCKS reply → connection refused.
     */
    fun streamEndToSocks5(reason: Int): Int = when (reason and STREAM_REASON_MASK) {
        0 -> SOCKS5_SUCCEEDED
        STREAM_MISC -> SOCKS5_GENERAL_ERROR
        STREAM_RESOLVEFAILED -> SOCKS5_HOST_UNREACHABLE
        STREAM_CONNECTREFUSED -> SOCKS5_CONNECTION_REFUSED
        STREAM_ENTRYPOLICY, STREAM_EXITPOLICY -> SOCKS5_NOT_ALLOWED
        STREAM_DESTROY -> SOCKS5_GENERAL_ERROR
        STREAM_DONE -> SOCKS5_CONNECTION_REFUSED
        STREAM_TIMEOUT -> SOCKS5_TTL_EXPIRED
        STREAM_NOROUTE -> SOCKS5_HOST_UNREACHABLE
        STREAM_RESOURCELIMIT, STREAM_HIBERNATING, STREAM_INTERNAL,
        STREAM_TORPROTOCOL, STREAM_CANT_ATTACH, STREAM_PRIVATE_ADDR,
        STREAM_SOCKSPROTOCOL, STREAM_HTTPPROTOCOL,
        -> SOCKS5_GENERAL_ERROR
        STREAM_CONNRESET -> SOCKS5_CONNECTION_REFUSED
        STREAM_NET_UNREACHABLE -> SOCKS5_NET_UNREACHABLE
        else -> SOCKS5_GENERAL_ERROR
    }

    /** C Tor `stream_end_reason_to_string`. */
    fun streamEndReasonToString(reason: Int): String = streamEndToString(reason)

    /** C Tor `stream_end_reason_to_socks5_response`. */
    fun streamEndReasonToSocks5Response(reason: Int): Int = streamEndToSocks5(reason)

    /** C Tor `orconn_end_reason_to_control_string`. */
    fun orconnEndReasonToControlString(reason: Int): String = orconnEndToControl(reason)

    /** C Tor `orconn_end_reason_to_control_string`. */
    fun orconnEndToControl(reason: Int): String = when (reason) {
        ORCONN_DONE -> "DONE"
        ORCONN_REFUSED -> "CONNECTREFUSED"
        ORCONN_IDENTITY -> "IDENTITY"
        ORCONN_CONNRESET -> "CONNECTRESET"
        ORCONN_TIMEOUT -> "TIMEOUT"
        ORCONN_NO_ROUTE -> "NOROUTE"
        ORCONN_IO_ERROR -> "IOERROR"
        ORCONN_RESOURCE_LIMIT -> "RESOURCELIMIT"
        ORCONN_TLS_ERROR -> "TLS_ERROR"
        ORCONN_MISC -> "MISC"
        ORCONN_PT_MISSING -> "PT_MISSING"
        0 -> ""
        else -> "UNKNOWN"
    }

    /** C Tor `tls_error_to_orconn_end_reason`. */
    fun tlsErrorToOrconnEndReason(tlsError: Int): Int = when (tlsError) {
        TOR_TLS_ERROR_IO -> ORCONN_IO_ERROR
        TOR_TLS_ERROR_CONNREFUSED -> ORCONN_REFUSED
        TOR_TLS_ERROR_CONNRESET -> ORCONN_CONNRESET
        TOR_TLS_ERROR_NO_ROUTE -> ORCONN_NO_ROUTE
        TOR_TLS_ERROR_TIMEOUT -> ORCONN_TIMEOUT
        TOR_TLS_WANTREAD, TOR_TLS_WANTWRITE, TOR_TLS_CLOSE, TOR_TLS_DONE -> ORCONN_DONE
        TOR_TLS_ERROR_MISC -> ORCONN_TLS_ERROR
        else -> ORCONN_MISC
    }

    /** C Tor `errno_to_stream_end_reason` (Linux errno set). */
    fun errnoToStreamEndReason(errno: Int): Int = when (errno) {
        Errno.EPIPE -> STREAM_DONE
        Errno.EBADF, Errno.EFAULT, Errno.EINVAL, Errno.EISCONN, Errno.ENOTSOCK,
        Errno.EPROTONOSUPPORT, Errno.EAFNOSUPPORT, Errno.ENOTCONN,
        -> STREAM_INTERNAL
        Errno.ENETUNREACH, Errno.EHOSTUNREACH, Errno.EACCES, Errno.EPERM -> STREAM_NOROUTE
        Errno.ECONNREFUSED -> STREAM_CONNECTREFUSED
        Errno.ECONNRESET -> STREAM_CONNRESET
        Errno.ETIMEDOUT -> STREAM_TIMEOUT
        Errno.ENOBUFS, Errno.ENOMEM, Errno.ENFILE, Errno.EADDRINUSE,
        Errno.EADDRNOTAVAIL, Errno.EMFILE,
        -> STREAM_RESOURCELIMIT
        else -> STREAM_MISC
    }

    /** C Tor `errno_to_orconn_end_reason` (Linux errno set). */
    fun errnoToOrconnEndReason(errno: Int): Int = when (errno) {
        Errno.EPIPE -> ORCONN_DONE
        Errno.ENOTCONN, Errno.ENETUNREACH, Errno.ENETDOWN, Errno.EHOSTUNREACH -> ORCONN_NO_ROUTE
        Errno.ECONNREFUSED -> ORCONN_REFUSED
        Errno.ECONNRESET -> ORCONN_CONNRESET
        Errno.ETIMEDOUT -> ORCONN_TIMEOUT
        Errno.ENOBUFS, Errno.ENOMEM, Errno.ENFILE, Errno.EMFILE,
        Errno.EACCES, Errno.EBADF, Errno.EFAULT, Errno.EINVAL,
        -> ORCONN_RESOURCE_LIMIT
        else -> ORCONN_MISC
    }

    fun socks4ResponseCodeToString(code: Int): String = when (code and 0xff) {
        0x5a -> "connection accepted"
        0x5b -> "server rejected connection"
        0x5c -> "server cannot connect to identd on this client"
        0x5d -> "user id does not match identd"
        else -> "invalid SOCKS 4 response code"
    }

    fun socks5ResponseCodeToString(code: Int): String = when (code and 0xff) {
        0x00 -> "connection accepted"
        0x01 -> "general SOCKS server failure"
        0x02 -> "connection not allowed by ruleset"
        0x03 -> "Network unreachable"
        0x04 -> "Host unreachable"
        0x05 -> "Connection refused"
        0x06 -> "TTL expired"
        0x07 -> "Command not supported"
        0x08 -> "Address type not supported"
        else -> "unknown reason"
    }

    /** C Tor `end_reason_to_http_connect_response_line`. */
    fun endReasonToHttpConnectResponseLine(endreason: Int): String {
        val r = endreason and STREAM_REASON_MASK
        return when (r) {
            0 -> "HTTP/1.0 200 OK\r\n"
            STREAM_MISC -> "HTTP/1.0 500 Internal Server Error\r\n"
            STREAM_RESOLVEFAILED -> "HTTP/1.0 503 Service Unavailable (resolve failed)\r\n"
            STREAM_NOROUTE -> "HTTP/1.0 503 Service Unavailable (no route)\r\n"
            STREAM_CONNECTREFUSED -> "HTTP/1.0 403 Forbidden (connection refused)\r\n"
            STREAM_EXITPOLICY -> "HTTP/1.0 403 Forbidden (exit policy)\r\n"
            STREAM_DESTROY -> "HTTP/1.0 502 Bad Gateway (destroy cell received)\r\n"
            STREAM_DONE -> "HTTP/1.0 502 Bad Gateway (unexpected close)\r\n"
            STREAM_TIMEOUT -> "HTTP/1.0 504 Gateway Timeout\r\n"
            STREAM_HIBERNATING -> "HTTP/1.0 502 Bad Gateway (hibernating server)\r\n"
            STREAM_INTERNAL -> "HTTP/1.0 502 Bad Gateway (internal error)\r\n"
            STREAM_RESOURCELIMIT -> "HTTP/1.0 502 Bad Gateway (resource limit)\r\n"
            STREAM_CONNRESET -> "HTTP/1.0 403 Forbidden (connection reset)\r\n"
            STREAM_TORPROTOCOL -> "HTTP/1.0 502 Bad Gateway (tor protocol violation)\r\n"
            STREAM_ENTRYPOLICY -> "HTTP/1.0 403 Forbidden (entry policy violation)\r\n"
            else -> "HTTP/1.0 500 Internal Server Error (weird end reason)\r\n"
        }
    }

    // —— bandwidth_weight_rule_t (node_select.h / reasons.c) ——
    const val NO_WEIGHTING: Int = 0
    const val WEIGHT_FOR_EXIT: Int = 1
    const val WEIGHT_FOR_MID: Int = 2
    const val WEIGHT_FOR_GUARD: Int = 3
    const val WEIGHT_FOR_DIR: Int = 4

    /** C Tor `bandwidth_weight_rule_to_string`. */
    fun bandwidthWeightRuleToString(rule: Int): String = when (rule) {
        NO_WEIGHTING -> "no weighting"
        WEIGHT_FOR_EXIT -> "weight as exit"
        WEIGHT_FOR_MID -> "weight as middle node"
        WEIGHT_FOR_GUARD -> "weight as guard"
        WEIGHT_FOR_DIR -> "weight as directory"
        else -> "unknown rule"
    }
}

/**
 * Circuit purpose tags (C Tor `CIRCUIT_PURPOSE_*` in `circuitlist.h`).
 *
 * [code] matches C Tor numeric values where applicable. Aggregates such as
 * [HS_CLIENT_INTRO] keep controller wire names used by existing call sites.
 */
enum class CircuitPurpose(val code: Int, val wireName: String) {
    OR(1, "SERVER"),
    INTRO_POINT(2, "SERVER"),
    REND_POINT_WAITING(3, "SERVER"),
    REND_ESTABLISHED(4, "SERVER"),
    GENERAL(5, "GENERAL"),
    HS_CLIENT_INTRODUCING(6, "HS_CLIENT_INTRO"),
    HS_CLIENT_INTRO_ACK_WAIT(7, "HS_CLIENT_INTRO"),
    HS_CLIENT_INTRO_ACKED(8, "HS_CLIENT_INTRO"),
    /** Aggregate / alias for introducing (controller string). */
    HS_CLIENT_INTRO(6, "HS_CLIENT_INTRO"),
    HS_CLIENT_ESTABLISH_REND(9, "HS_CLIENT_REND"),
    HS_CLIENT_REND_READY(10, "HS_CLIENT_REND"),
    HS_CLIENT_REND_READY_INTRO_ACKED(11, "HS_CLIENT_REND"),
    HS_CLIENT_REND_JOINED(12, "HS_CLIENT_REND"),
    HS_CLIENT_REND(12, "HS_CLIENT_REND"),
    HS_CLIENT_HSDIR(13, "HS_CLIENT_HSDIR"),
    MEASURE_TIMEOUT(14, "MEASURE_TIMEOUT"),
    CIRCUIT_PADDING(15, "CIRCUIT_PADDING"),
    HS_SERVICE_ESTABLISH_INTRO(16, "HS_SERVICE_INTRO"),
    HS_SERVICE_INTRO(17, "HS_SERVICE_INTRO"),
    HS_SERVICE_CONNECT_REND(18, "HS_SERVICE_REND"),
    HS_SERVICE_REND_JOINED(19, "HS_SERVICE_REND"),
    HS_SERVICE_REND(19, "HS_SERVICE_REND"),
    HS_SERVICE_HSDIR(20, "HS_SERVICE_HSDIR"),
    TESTING(21, "TESTING"),
    CONTROLLER(22, "CONTROLLER"),
    PATH_BIAS_TESTING(23, "PATH_BIAS_TESTING"),
    HS_VANGUARDS(24, "HS_VANGUARDS"),
    CONFLUX_UNLINKED(25, "CONFLUX_UNLINKED"),
    CONFLUX_LINKED(26, "CONFLUX_LINKED"),
    /** kotlin-tor directory circuits (not a distinct C Tor purpose code). */
    DIR_FETCH(5, "DIR_FETCH"),
    DIR_UPLOAD(5, "DIR_UPLOAD"),
    ;

    companion object {
        fun fromCode(code: Int): CircuitPurpose? = entries.find { it.code == code && it != HS_CLIENT_INTRO && it != HS_CLIENT_REND && it != HS_SERVICE_REND }
    }
}
