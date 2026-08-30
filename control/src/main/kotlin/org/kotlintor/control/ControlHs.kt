package org.kotlintor.control

/**
 * Hidden-service control commands (C Tor `control_hs.c`).
 *
 * Inventory: `L1:feature/control/control_hs.c`
 *
 * ADD_ONION / DEL_ONION / HSFETCH / HSPOST are handled by [ControlServer].
 */
object ControlHs {
    val COMMANDS: Set<String> = setOf("ADD_ONION", "DEL_ONION", "HSFETCH", "HSPOST")

    fun isHsCommand(cmd: String): Boolean = cmd.uppercase() in COMMANDS

    /** Parse `Port=` entries from ADD_ONION args (`80,127.0.0.1:8080`). */
    fun parsePortMapping(token: String): Pair<Int, String>? {
        val body = token.removePrefix("Port=").removePrefix("port=")
        val comma = body.indexOf(',')
        if (comma <= 0) return null
        val virt = body.substring(0, comma).toIntOrNull() ?: return null
        val target = body.substring(comma + 1).trim()
        if (target.isEmpty()) return null
        return virt to target
    }
}
