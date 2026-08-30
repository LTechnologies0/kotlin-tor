package org.kotlintor.control

/**
 * One control reply line (C Tor `control_reply_line_t` subset).
 */
data class ControlReplyLine(
    var code: Int = 250,
    var text: String = "",
    var isDone: Boolean = false,
)

/**
 * Control protocol framing helpers (C Tor `control_proto.c`).
 *
 * Inventory: `L1:feature/control/control_proto.c`
 */
object ControlProto {
    const val PROTOCOLINFO_VERSION: Int = 1
    const val TOR_CONTROL_PORT_VERSION: String = "1"

    fun protocolInfoPreamble(): List<String> = listOf(
        "250-PROTOCOLINFO $PROTOCOLINFO_VERSION",
        "250-AUTH METHODS=COOKIE,SAFECOOKIE",
        "250 OK",
    )

    fun splitCommand(line: String): Pair<String, String> {
        val trimmed = line.trimEnd('\r', '\n')
        val sp = trimmed.indexOf(' ')
        return if (sp < 0) trimmed.uppercase() to ""
        else trimmed.substring(0, sp).uppercase() to trimmed.substring(sp + 1)
    }

    /** C Tor `control_split_incoming_command`. */
    fun controlSplitIncomingCommand(line: String): Pair<String, String> = splitCommand(line)

    fun isMultilinePlus(codeLine: String): Boolean =
        codeLine.length >= 4 && codeLine[3] == '+'

    /** C Tor `connection_write_str_to_buf`. */
    fun connectionWriteStrToBuf(s: String, conn: ControlConnection) {
        conn.outbuf.append(s)
    }

    /** C Tor `connection_printf_to_buf`. */
    fun connectionPrintfToBuf(conn: ControlConnection, format: String, vararg args: Any?) {
        conn.outbuf.append(format.format(*args))
    }

    /** C Tor `control_printf_endreply`. */
    fun controlPrintfEndreply(conn: ControlConnection, code: Int, msg: String) {
        conn.outbuf.append("$code $msg\r\n")
    }

    /** C Tor `control_printf_midreply`. */
    fun controlPrintfMidreply(conn: ControlConnection, code: Int, msg: String) {
        conn.outbuf.append("$code-$msg\r\n")
    }

    /** C Tor `control_printf_datareply`. */
    fun controlPrintfDatareply(conn: ControlConnection, code: Int, msg: String) {
        conn.outbuf.append("$code+$msg\r\n")
    }

    /** C Tor `control_reply_add_one_kv`. */
    fun controlReplyAddOneKv(reply: MutableList<ControlReplyLine>, code: Int, key: String, value: String) {
        reply += ControlReplyLine(code = code, text = "$key=$value")
    }

    /** C Tor `control_reply_append_kv`. */
    fun controlReplyAppendKv(reply: MutableList<ControlReplyLine>, key: String, value: String) {
        if (reply.isEmpty()) {
            controlReplyAddOneKv(reply, 250, key, value)
        } else {
            val last = reply.last()
            last.text = if (last.text.isEmpty()) "$key=$value" else "${last.text} $key=$value"
        }
    }

    /** C Tor `control_reply_add_str`. */
    fun controlReplyAddStr(reply: MutableList<ControlReplyLine>, code: Int, s: String) {
        reply += ControlReplyLine(code = code, text = s)
    }

    /** C Tor `control_reply_add_printf`. */
    fun controlReplyAddPrintf(reply: MutableList<ControlReplyLine>, code: Int, format: String, vararg args: Any?) {
        reply += ControlReplyLine(code = code, text = format.format(*args))
    }

    /** C Tor `control_reply_add_done`. */
    fun controlReplyAddDone(reply: MutableList<ControlReplyLine>) {
        reply += ControlReplyLine(code = 250, text = "OK", isDone = true)
    }

    /** C Tor `control_reply_clear`. */
    fun controlReplyClear(reply: MutableList<ControlReplyLine>) {
        reply.clear()
    }

    /** C Tor `control_reply_free_`. */
    fun controlReplyFree_(reply: MutableList<ControlReplyLine>?): MutableList<ControlReplyLine>? {
        reply?.clear()
        return null
    }

    /** C Tor `control_reply_line_free_`. */
    fun controlReplyLineFree_(line: ControlReplyLine?): ControlReplyLine? = null

    fun formatReply(reply: List<ControlReplyLine>): List<String> =
        reply.map { line ->
            when {
                line.isDone -> "${line.code} ${line.text}"
                else -> "${line.code}-${line.text}"
            }
        }

    /** C Tor `control_write_endreply`. */
    fun controlWriteEndreply(conn: ControlConnection, code: Int, msg: String) =
        controlPrintfEndreply(conn, code, msg)

    /** C Tor `control_write_midreply`. */
    fun controlWriteMidreply(conn: ControlConnection, code: Int, msg: String) =
        controlPrintfMidreply(conn, code, msg)

    /** C Tor `control_write_datareply`. */
    fun controlWriteDatareply(conn: ControlConnection, code: Int, msg: String) =
        controlPrintfDatareply(conn, code, msg)

    /** C Tor `control_write_data`. */
    fun controlWriteData(conn: ControlConnection, data: String) {
        conn.outbuf.append(data)
        if (!data.endsWith("\r\n")) conn.outbuf.append("\r\n")
        conn.outbuf.append(".\r\n")
    }

    /** C Tor `control_write_reply_line`. */
    fun controlWriteReplyLine(conn: ControlConnection, line: ControlReplyLine) {
        if (line.isDone) controlWriteEndreply(conn, line.code, line.text)
        else controlWriteMidreply(conn, line.code, line.text)
    }

    /** C Tor `control_write_reply_lines`. */
    fun controlWriteReplyLines(conn: ControlConnection, reply: List<ControlReplyLine>) {
        for (line in reply) controlWriteReplyLine(conn, line)
    }

    /** C Tor `control_vprintf_reply` — format into outbuf with trailing CRLF. */
    fun controlVprintfReply(conn: ControlConnection, code: Int, format: String, vararg args: Any?) {
        controlPrintfEndreply(conn, code, format.format(*args))
    }

    /** C Tor `send_control_done`. */
    fun sendControlDone(conn: ControlConnection) {
        controlPrintfEndreply(conn, 250, "OK")
    }

    /**
     * C Tor `write_escaped_data` — CRLF normalize, dot-stuff, terminate with `.\r\n`.
     */
    fun writeEscapedData(data: String): String {
        val sb = StringBuilder(data.length + 8)
        var startOfLine = true
        var i = 0
        while (i < data.length) {
            val ch = data[i]
            when (ch) {
                '\n' -> {
                    if (i == 0 || data[i - 1] != '\r') sb.append('\r')
                    sb.append('\n')
                    startOfLine = true
                }
                '.' -> {
                    if (startOfLine) sb.append('.')
                    sb.append('.')
                    startOfLine = false
                }
                else -> {
                    sb.append(ch)
                    startOfLine = false
                }
            }
            i++
        }
        if (sb.length < 2 || sb.substring(sb.length - 2) != "\r\n") {
            sb.append("\r\n")
        }
        sb.append(".\r\n")
        return sb.toString()
    }

    /**
     * C Tor `read_escaped_data` — undo dot-stuffing; CRLF → LF.
     */
    fun readEscapedData(data: String): String {
        val sb = StringBuilder(data.length)
        var i = 0
        while (i < data.length) {
            // start of line
            if (data[i] == '.') i++
            val nl = data.indexOf('\n', i)
            if (nl < 0) {
                sb.append(data, i, data.length)
                break
            }
            var end = nl
            if (end > i && data[end - 1] == '\r') end--
            sb.append(data, i, end)
            sb.append('\n')
            i = nl + 1
        }
        return sb.toString()
    }
}
