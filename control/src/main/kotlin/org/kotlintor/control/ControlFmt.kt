package org.kotlintor.control

/**
 * Control reply / event line formatting (C Tor `control_fmt.c`).
 *
 * Inventory: `L1:feature/control/control_fmt.c`
 */
object ControlFmt {
    fun ok(): String = "250 OK"

    fun err(code: Int, msg: String): String = "$code $msg"

    fun dataStart(key: String): String = "250+$key="

    fun dataEnd(): String = "."

    fun kv(key: String, value: String): String = "250-$key=$value"

    fun escapeQuoted(s: String): String =
        s.replace('\\', '/').replace('"', '\'')

    fun circEvent(id: Long, status: String, path: String = ""): String =
        if (path.isEmpty()) "650 CIRC $id $status"
        else "650 CIRC $id $status $path"

    fun orconnEvent(status: String, target: String): String =
        "650 ORCONN $target $status"

    /**
     * C Tor `circuit_describe_status_for_controller` — path + PURPOSE/BUILD_FLAGS subset.
     */
    fun circuitDescribeStatusForController(
        circId: Long,
        path: String = "",
        purpose: String = "GENERAL",
        onehopTunnel: Boolean = false,
        isInternal: Boolean = false,
        needCapacity: Boolean = false,
        needUptime: Boolean = false,
        timeCreated: String? = null,
    ): String {
        val parts = mutableListOf<String>()
        if (path.isNotEmpty()) parts += path
        val flags = buildList {
            if (onehopTunnel) add("ONEHOP_TUNNEL")
            if (isInternal) add("IS_INTERNAL")
            if (needCapacity) add("NEED_CAPACITY")
            if (needUptime) add("NEED_UPTIME")
        }
        if (flags.isNotEmpty()) parts += "BUILD_FLAGS=${flags.joinToString(",")}"
        parts += "PURPOSE=$purpose"
        if (timeCreated != null) parts += "TIME_CREATED=$timeCreated"
        parts += "ID=$circId"
        return parts.joinToString(" ")
    }

    /** Alias used by inventory naming for entry streams (delegates to [Control]). */
    fun entryConnectionDescribeStatusForController(
        streamId: Long,
        target: String,
        status: String = "NEW",
    ): String = Control.entryConnectionDescribeStatusForController(streamId, target, status)

    /**
     * C Tor `write_stream_target_to_buf` — `host[.exitnick.exit|.onion]:port`.
     */
    fun writeStreamTargetToBuf(
        address: String,
        port: Int,
        chosenExitName: String? = null,
        rendezvous: Boolean = false,
    ): String {
        val suffix =
            when {
                chosenExitName != null -> ".${chosenExitName}.exit"
                rendezvous -> ".onion"
                else -> ""
            }
        return "$address$suffix:$port"
    }
}
