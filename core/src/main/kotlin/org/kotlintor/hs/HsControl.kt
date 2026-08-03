package org.kotlintor.hs

/**
 * HS control-port events / HSPOST·HSFETCH hooks (C Tor `hs_control.c`).
 *
 * Inventory: `L1:feature/hs/hs_control.c`
 *
 * Event strings feed [org.kotlintor.TorEvent.HsDesc] via [ControlServer] / [TorDaemon.emit].
 */
object HsControl {
    /** Strip leading "650 " so TorEvent.HsDesc + ControlServer can re-prefix uniformly. */
    fun descEventRequested(onionAddress: String, blindedB64: String, hsDirId: String): String =
        "HS_DESC REQUESTED $onionAddress NO_AUTH $hsDirId $blindedB64"

    fun descEventFailed(onionAddress: String, hsDirId: String, reason: String): String =
        "HS_DESC FAILED $onionAddress NO_AUTH $hsDirId $reason"

    fun descEventReceived(onionAddress: String, hsDirId: String): String =
        "HS_DESC RECEIVED $onionAddress NO_AUTH $hsDirId"

    fun descEventCreated(onionAddress: String, blindedB64: String): String =
        "HS_DESC CREATED $onionAddress $blindedB64"

    fun descEventUpload(onionAddress: String, hsDirId: String, blindedB64: String): String =
        "HS_DESC UPLOAD $onionAddress NO_AUTH $hsDirId $blindedB64"

    fun descEventUploaded(onionAddress: String, hsDirId: String): String =
        "HS_DESC UPLOADED $onionAddress NO_AUTH $hsDirId"

    fun descEventContent(onionAddress: String, hsDirId: String, bodyLen: Int): String =
        "HS_DESC_CONTENT $onionAddress NO_AUTH $hsDirId ($bodyLen bytes)"

    /** HSPOST acceptance gate (body non-empty). Full HSDir fan-out not ported. */
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
}
