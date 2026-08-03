package org.kotlintor.dir

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * Format `routerstatus_t` lines (C Tor `fmt_routerstatus.c`).
 */
object FmtRouterStatus {
    enum class Format {
        /** Full vote / control-port style: r + s + optional v/w/p. */
        CONTROL_PORT,
        /** Consensus stub: r line only (no s). */
        V3_CONSENSUS,
        /** Microdesc consensus: r without descriptor digest. */
        V3_CONSENSUS_MICRODESC,
        /** Vote: r + s + extras. */
        V3_VOTE,
    }

    private val ISO: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)

    private val FLAG_ORDER = listOf(
        "Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "MiddleOnly",
        "Running", "Stable", "StaleDesc", "Sybil", "V2Dir", "Valid",
    )

    fun formatEntry(
        rs: RouterStatus,
        format: Format = Format.CONTROL_PORT,
        version: String? = rs.version,
        protocols: String? = null,
        ipv6: String? = null,
        ipv6OrPort: Int? = null,
    ): String {
        val published = ISO.format(rs.publication)
        val id64 = digestToBase64(rs.identity)
        val dig64 = digestToBase64(rs.digest)
        val sb = StringBuilder()
        when (format) {
            Format.V3_CONSENSUS_MICRODESC ->
                sb.append("r ${rs.nickname} $id64 $published ${rs.ip} ${rs.orPort} ${rs.dirPort}\n")
            else ->
                sb.append("r ${rs.nickname} $id64 $dig64 $published ${rs.ip} ${rs.orPort} ${rs.dirPort}\n")
        }
        if (ipv6 != null && ipv6OrPort != null) {
            sb.append("a $ipv6:$ipv6OrPort\n")
        }
        if (format == Format.V3_CONSENSUS || format == Format.V3_CONSENSUS_MICRODESC) {
            return sb.toString()
        }
        sb.append('s')
        for (f in FLAG_ORDER) {
            if (f in rs.flags) sb.append(' ').append(f)
        }
        sb.append('\n')
        val ver = version
        if (!ver.isNullOrBlank()) sb.append("v $ver\n")
        if (rs.bandwidth > 0) sb.append("w Bandwidth=${rs.bandwidth}\n")
        val proto = protocols ?: rs.proto.entries.joinToString(" ") { "${it.key}=${it.value}" }
        if (proto.isNotBlank()) sb.append("pr $proto\n")
        return sb.toString()
    }

    /** Tor `digest_to_base64`: standard base64 without padding. */
    fun digestToBase64(digest: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(digest)
}
