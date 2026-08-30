package org.kotlintor.hs

/**
 * HS control-port events / HSPOST·HSFETCH (C Tor `hs_control.c`).
 *
 * Event strings feed [org.kotlintor.TorEvent.HsDesc] via ControlServer / TorDaemon.emit.
 * Inventory: `L1:feature/hs/hs_control.c`
 */
object HsControl {
    /** C Tor `rend_auth_type_t` subset used in HS_DESC lines. */
    enum class AuthType(val wire: String) {
        NO_AUTH("NO_AUTH"),
        BASIC_AUTH("BASIC_AUTH"),
        STEALTH_AUTH("STEALTH_AUTH"),
    }

    /** Common failure reason tokens (control-spec / hs_control). */
    object FailReason {
        const val BAD_DESC = "BAD_DESC"
        const val QUERY_REJECTED = "QUERY_REJECTED"
        const val NOT_FOUND = "NOT_FOUND"
        const val UNEXPECTED = "UNEXPECTED"
        const val QUERY_NO_HSDIR = "QUERY_NO_HSDIR"
        const val QUERY_NO_HS_DESC = "QUERY_NO_HS_DESC"
    }

    /** Strip leading "650 " so TorEvent.HsDesc + ControlServer can re-prefix uniformly. */
    fun descEventRequested(
        onionAddress: String,
        blindedB64: String,
        hsDirId: String,
        auth: AuthType = AuthType.NO_AUTH,
        hsDirIndexHex: String? = null,
    ): String = buildString {
        append("HS_DESC REQUESTED $onionAddress ${auth.wire} $hsDirId $blindedB64")
        if (hsDirIndexHex != null) append(" $hsDirIndexHex")
    }

    fun descEventFailed(
        onionAddress: String,
        hsDirId: String,
        reason: String,
        auth: AuthType = AuthType.NO_AUTH,
        blindedB64: String? = null,
    ): String = buildString {
        append("HS_DESC FAILED $onionAddress ${auth.wire} $hsDirId")
        if (blindedB64 != null) append(" $blindedB64")
        append(" $reason")
    }

    fun descEventReceived(
        onionAddress: String,
        hsDirId: String,
        auth: AuthType = AuthType.NO_AUTH,
        blindedB64: String? = null,
    ): String = buildString {
        append("HS_DESC RECEIVED $onionAddress ${auth.wire} $hsDirId")
        if (blindedB64 != null) append(" $blindedB64")
    }

    fun descEventCreated(onionAddress: String, blindedB64: String): String =
        "HS_DESC CREATED $onionAddress $blindedB64"

    fun descEventUpload(
        onionAddress: String,
        hsDirId: String,
        blindedB64: String,
        auth: AuthType = AuthType.NO_AUTH,
        hsDirIndexHex: String? = null,
    ): String = buildString {
        append("HS_DESC UPLOAD $onionAddress ${auth.wire} $hsDirId $blindedB64")
        if (hsDirIndexHex != null) append(" $hsDirIndexHex")
    }

    fun descEventUploaded(
        onionAddress: String,
        hsDirId: String,
        auth: AuthType = AuthType.NO_AUTH,
    ): String = "HS_DESC UPLOADED $onionAddress ${auth.wire} $hsDirId"

    /**
     * C Tor `hs_control_desc_event_content` / control `HS_DESC_CONTENT`.
     * When [body] is non-null, append a blank line then the descriptor body
     * (control-spec multiline after the keyword line).
     */
    fun descEventContent(
        onionAddress: String,
        hsDirId: String,
        body: String? = null,
        auth: AuthType = AuthType.NO_AUTH,
        blindedB64: String? = null,
    ): String = buildString {
        append("HS_DESC_CONTENT $onionAddress ${auth.wire} $hsDirId")
        if (blindedB64 != null) append(" $blindedB64")
        if (body != null) {
            append("\r\n")
            append(body)
            if (!body.endsWith("\n")) append("\r\n")
            append(".")
        } else {
            append(" (${0} bytes)")
        }
    }

    /** Convenience for callers that only know body length (legacy). */
    fun descEventContent(onionAddress: String, hsDirId: String, bodyLen: Int): String =
        "HS_DESC_CONTENT $onionAddress ${AuthType.NO_AUTH.wire} $hsDirId ($bodyLen bytes)"

    /** HSPOST acceptance gate (body non-empty). */
    fun hsPostAccepted(body: String, onionAddress: String?): Boolean =
        body.isNotBlank() && (onionAddress == null || onionAddress.endsWith(".onion"))

    /** HSFETCH acceptance gate: onion address or 32-byte identity hex. */
    fun hsFetchAccepted(identityOrOnion: String): Boolean {
        val s = identityOrOnion.trim()
        if (s.endsWith(".onion", ignoreCase = true)) {
            val base = s.removeSuffix(".onion").removeSuffix(".ONION")
            return base.length in 56..62
        }
        return s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }

    /** Parse SERVER= hints from HSFETCH/HSPOST args. */
    fun parseServerHints(args: List<String>): List<String> =
        args.mapNotNull { a ->
            when {
                a.startsWith("SERVER=", ignoreCase = true) -> a.substringAfter('=')
                a.startsWith("HSDir=", ignoreCase = true) -> a.substringAfter('=')
                else -> null
            }
        }

    /** C Tor `hs_control_desc_event_content`. */
    fun hsControlDescEventContent(
        onionAddress: String,
        hsDirId: String,
        body: String? = null,
        auth: AuthType = AuthType.NO_AUTH,
        blindedB64: String? = null,
    ): String = descEventContent(onionAddress, hsDirId, body, auth, blindedB64)

    /** C Tor `hs_control_desc_event_created`. */
    fun hsControlDescEventCreated(onionAddress: String, blindedB64: String): String =
        descEventCreated(onionAddress, blindedB64)

    /** C Tor `hs_control_desc_event_failed`. */
    fun hsControlDescEventFailed(
        onionAddress: String,
        hsDirId: String,
        reason: String,
        auth: AuthType = AuthType.NO_AUTH,
        blindedB64: String? = null,
    ): String = descEventFailed(onionAddress, hsDirId, reason, auth, blindedB64)

    /** C Tor `hs_control_desc_event_received`. */
    fun hsControlDescEventReceived(
        onionAddress: String,
        hsDirId: String,
        auth: AuthType = AuthType.NO_AUTH,
        blindedB64: String? = null,
    ): String = descEventReceived(onionAddress, hsDirId, auth, blindedB64)

    /** C Tor `hs_control_desc_event_requested`. */
    fun hsControlDescEventRequested(
        onionAddress: String,
        blindedB64: String,
        hsDirId: String,
        auth: AuthType = AuthType.NO_AUTH,
        hsDirIndexHex: String? = null,
    ): String = descEventRequested(onionAddress, blindedB64, hsDirId, auth, hsDirIndexHex)

    /** C Tor `hs_control_desc_event_upload`. */
    fun hsControlDescEventUpload(
        onionAddress: String,
        hsDirId: String,
        blindedB64: String,
        auth: AuthType = AuthType.NO_AUTH,
        hsDirIndexHex: String? = null,
    ): String = descEventUpload(onionAddress, hsDirId, blindedB64, auth, hsDirIndexHex)

    /** C Tor `hs_control_desc_event_uploaded`. */
    fun hsControlDescEventUploaded(
        onionAddress: String,
        hsDirId: String,
        auth: AuthType = AuthType.NO_AUTH,
    ): String = descEventUploaded(onionAddress, hsDirId, auth)

    /** C Tor `hs_control_hsfetch_command`. */
    fun hsControlHsfetchCommand(identityOrOnion: String, servers: List<String> = emptyList()): Boolean =
        hsFetchAccepted(identityOrOnion)

    /** C Tor `hs_control_hspost_command`. */
    fun hsControlHspostCommand(body: String, onionAddress: String?): Boolean =
        hsPostAccepted(body, onionAddress)
}
