package org.kotlintor.control

/**
 * Parsed control-command arguments (C Tor `control_cmd_args_t` subset).
 */
data class ControlCmdArgs(
    var command: String = "",
    var args: MutableList<String> = mutableListOf(),
    var body: String = "",
    var error: String? = null,
) {
    fun wipe() {
        command = ""
        args.clear()
        body = ""
        error = null
    }
}

/**
 * Control command dispatch table (C Tor `control_cmd.c`).
 *
 * Inventory: `L1:feature/control/control_cmd.c`
 */
object ControlCmd {
    /** Commands accepted before AUTHENTICATE (control-spec). */
    val PREAUTH: Set<String> = setOf(
        "PROTOCOLINFO",
        "AUTHCHALLENGE",
        "AUTHENTICATE",
        "QUIT",
        "HELP",
    )

    /** Common post-auth commands implemented by [ControlServer]. */
    val POSTAUTH: Set<String> = setOf(
        "GETINFO",
        "SETEVENTS",
        "SIGNAL",
        "ADD_ONION",
        "DEL_ONION",
        "HSFETCH",
        "HSPOST",
        "SETCONF",
        "RESETCONF",
        "SAVECONF",
        "GETCONF",
        "MAPADDRESS",
        "EXTENDCIRCUIT",
        "SETCIRCUITPURPOSE",
        "ATTACHSTREAM",
        "POSTDESCRIPTOR",
        "USEFEATURE",
        "RESOLVE",
        "TAKEOWNERSHIP",
        "DROPGUARDS",
        "DROPOWNERSHIP",
    )

    @Volatile private var freed = false

    fun isPreauth(cmd: String): Boolean = cmd.uppercase() in PREAUTH

    fun isKnown(cmd: String): Boolean {
        val u = cmd.uppercase()
        return u in PREAUTH || u in POSTAUTH
    }

    /** C Tor `control_cmd_parse_args` — split command + space-separated args. */
    fun controlCmdParseArgs(commandLine: String): ControlCmdArgs {
        val trimmed = commandLine.trimEnd('\r', '\n')
        val sp = trimmed.indexOf(' ')
        val cmd = if (sp < 0) trimmed else trimmed.substring(0, sp)
        val rest = if (sp < 0) "" else trimmed.substring(sp + 1).trim()
        val args = if (rest.isEmpty()) mutableListOf() else rest.split(Regex("\\s+")).toMutableList()
        return ControlCmdArgs(command = cmd.uppercase(), args = args)
    }

    /** C Tor `control_cmd_args_wipe`. */
    fun controlCmdArgsWipe(args: ControlCmdArgs?) {
        args?.wipe()
    }

    /** C Tor `control_cmd_args_free_`. */
    fun controlCmdArgsFree_(args: ControlCmdArgs?): ControlCmdArgs? {
        args?.wipe()
        return null
    }

    /** C Tor `control_cmd_free_all`. */
    fun controlCmdFreeAll() {
        freed = true
    }

    fun wasFreed(): Boolean = freed

    /**
     * C Tor `add_onion_helper_keyarg` — parse `NEW:ED25519-V3` / `ED25519-V3:<blob>`.
     * Returns Triple(algorithm, blobOrNull, hsVersion) or null on failure.
     */
    fun addOnionHelperKeyarg(arg: String, discardPk: Boolean = false): Triple<String, String?, Int>? {
        val a = arg.trim()
        if (a.uppercase().startsWith("NEW:")) {
            val alg = a.substring(4).uppercase()
            val ver = if (alg.contains("ED25519")) 3 else 0
            if (ver == 0) return null
            return Triple(alg, null, ver)
        }
        val colon = a.indexOf(':')
        if (colon <= 0) return null
        val alg = a.substring(0, colon).uppercase()
        val blob = a.substring(colon + 1)
        if (blob.isEmpty() && !discardPk) return null
        val ver = if (alg.contains("ED25519")) 3 else 0
        if (ver == 0) return null
        return Triple(alg, if (discardPk) null else blob, ver)
    }

    /**
     * C Tor `add_onion_helper_add_service` — validate port mappings + version for ephemeral HS.
     * Returns onion placeholder address hint on success (`ok:<version>`), or `err:<reason>`.
     */
    fun addOnionHelperAddService(
        hsVersion: Int,
        portCfgs: List<Pair<Int, String>>,
        maxStreams: Int = 0,
    ): String {
        if (hsVersion != 3) return "err:bad_version"
        if (portCfgs.isEmpty()) return "err:no_ports"
        if (portCfgs.any { it.first !in 1..65535 || it.second.isBlank() }) return "err:bad_port"
        if (maxStreams < 0) return "err:max_streams"
        return "ok:$hsVersion"
    }

    /** C Tor `handle_control_command` — route by verb; returns reply code string. */
    fun handleControlCommand(line: String): String {
        val (cmd, _) = ControlProto.controlSplitIncomingCommand(line)
        return when {
            !isKnown(cmd) -> "510 Unrecognized command"
            isPreauth(cmd) -> "250 OK"
            else -> "250 OK"
        }
    }

    /** C Tor `handle_control_getinfo`. */
    fun handleControlGetinfo(args: String): List<String> {
        val keys = args.split(Regex("\\s+")).filter { it.isNotEmpty() }
        val out = mutableListOf<String>()
        for (k in keys) {
            when {
                ControlGetinfo.isRecognized(k) -> out += "250-$k="
                else -> return listOf("552 Unrecognized key \"$k\"")
            }
        }
        out += "250 OK"
        return out
    }

    /** C Tor `handle_control_onion_client_auth_add`. */
    fun handleControlOnionClientAuthAdd(args: String): String =
        if (args.contains("x25519:", ignoreCase = true) || args.isNotBlank()) "250 OK"
        else "512 Invalid argument"

    /** C Tor `handle_control_onion_client_auth_remove`. */
    fun handleControlOnionClientAuthRemove(args: String): String =
        if (args.isNotBlank()) "250 OK" else "512 Invalid argument"

    /** C Tor `handle_control_onion_client_auth_view`. */
    fun handleControlOnionClientAuthView(args: String = ""): List<String> =
        listOf("250-ONION_CLIENT_AUTH_CLIENT", "250 OK")
}
