package org.kotlintor.dir

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * Format `routerstatus_t` lines (C Tor `fmt_routerstatus.c` /
 * `routerstatus_format_entry`).
 *
 * Inventory: `L1:feature/nodelist/fmt_routerstatus.c`
 */
object FmtRouterStatus {
    enum class Format {
        /** Legacy V2 NS opinion (r + s + optional v). */
        V2,
        /** Full vote / control-port style: r + s + optional v/w/p. */
        CONTROL_PORT,
        /** Consensus stub: r line only (no s). */
        V3_CONSENSUS,
        /** Microdesc consensus: r without descriptor digest. */
        V3_CONSENSUS_MICRODESC,
        /** Vote: r + s + Measured / GuardFraction / id / stats extras. */
        V3_VOTE,
    }

    /**
     * Extra vote fields (C Tor `vote_routerstatus_t` subset).
     */
    data class VoteExtras(
        val publishedOn: Instant? = null,
        val measuredBwKb: Int? = null,
        val isAuthority: Boolean = false,
        val guardFractionPercent: Int? = null,
        val ed25519Id: ByteArray? = null,
        val exitPolicySummary: String? = null,
        val statsWfu: Double? = null,
        val statsTk: Long? = null,
        val statsMtbf: Double? = null,
    )

    private val ISO: DateTimeFormatter =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)

    private val FLAG_ORDER = listOf(
        "Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "MiddleOnly",
        "Running", "Stable", "StaleDesc", "Sybil", "V2Dir", "Valid",
    )

    private const val DEFAULT_PUBLISHED = "2038-01-01 00:00:00"
    private const val MAX_V_LINE_LEN = 128
    private const val V_LINE_OVERHEAD = 7

    fun formatEntry(
        rs: RouterStatus,
        format: Format = Format.CONTROL_PORT,
        version: String? = rs.version,
        protocols: String? = null,
        ipv6: String? = null,
        ipv6OrPort: Int? = null,
        declaredPublishTime: Instant? = null,
        vote: VoteExtras? = null,
    ): String {
        val published = when {
            declaredPublishTime != null -> ISO.format(declaredPublishTime)
            vote?.publishedOn != null -> ISO.format(vote.publishedOn)
            else -> ISO.format(rs.publication)
        }.ifBlank { DEFAULT_PUBLISHED }

        if (rs.ip.isBlank()) return ""

        val id64 = digestToBase64(rs.identity)
        val dig64 = digestToBase64(rs.digest)
        val sb = StringBuilder()
        when (format) {
            Format.V3_CONSENSUS_MICRODESC ->
                sb.append("r ${rs.nickname} $id64 $published ${rs.ip} ${rs.orPort} ${rs.dirPort}\n")
            else ->
                sb.append("r ${rs.nickname} $id64 $dig64 $published ${rs.ip} ${rs.orPort} ${rs.dirPort}\n")
        }
        val v6 = ipv6 ?: null
        val v6port = ipv6OrPort
        if (!v6.isNullOrBlank() && v6port != null) {
            sb.append("a $v6:$v6port\n")
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
        if (!ver.isNullOrBlank() && ver.length < MAX_V_LINE_LEN - V_LINE_OVERHEAD) {
            sb.append("v $ver\n")
        }
        val proto = protocols ?: rs.proto.entries.joinToString(" ") { "${it.key}=${it.value}" }
        if (proto.isNotBlank()) sb.append("pr $proto\n")

        if (format == Format.V2) {
            return sb.toString()
        }

        val bwKb = when {
            format == Format.CONTROL_PORT && rs.bandwidth > 0 -> rs.bandwidth
            rs.bandwidth > 0 -> rs.bandwidth
            else -> 0L
        }
        if (bwKb > 0 || format == Format.V3_VOTE || format == Format.CONTROL_PORT) {
            sb.append("w Bandwidth=$bwKb")
            if (format == Format.V3_VOTE && vote?.measuredBwKb != null) {
                if (vote.isAuthority || "Authority" in rs.flags) {
                    sb.append(" MeasuredButAuthority=${vote.measuredBwKb}")
                } else {
                    sb.append(" Measured=${vote.measuredBwKb}")
                }
            }
            if (format == Format.V3_VOTE && vote?.guardFractionPercent != null) {
                sb.append(" GuardFraction=${vote.guardFractionPercent}")
            }
            sb.append('\n')
        }

        val policy = vote?.exitPolicySummary
        if (!policy.isNullOrBlank()) {
            sb.append("p $policy\n")
        }

        if (format == Format.V3_VOTE && vote != null) {
            val ed = vote.ed25519Id ?: rs.ed25519Identity
            if (ed == null || ed.all { it == 0.toByte() }) {
                sb.append("id ed25519 none\n")
            } else {
                sb.append("id ed25519 ${digest256ToBase64(ed)}\n")
            }
            if (vote.statsWfu != null && vote.statsTk != null && vote.statsMtbf != null) {
                sb.append(
                    "stats wfu=${"%.6f".format(java.util.Locale.US, vote.statsWfu)} tk=${vote.statsTk} " +
                        "mtbf=${"%.0f".format(java.util.Locale.US, vote.statsMtbf)}\n",
                )
            }
        }
        return sb.toString()
    }

    /** Tor `digest_to_base64`: standard base64 without padding (20-byte SHA1). */
    fun digestToBase64(digest: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(digest)

    /** Tor `digest256_to_base64` for ed25519 ids. */
    fun digest256ToBase64(digest: ByteArray): String =
        Base64.getEncoder().withoutPadding().encodeToString(digest)
}
