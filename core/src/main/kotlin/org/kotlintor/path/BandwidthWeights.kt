package org.kotlintor.path

import org.kotlintor.dir.RouterStatus

/**
 * Consensus `bandwidth-weights` / params Wxx (path-spec).
 * Weight = bandwidth * Wrole / bwweightscale.
 */
class BandwidthWeights(
    private val scale: Long,
    private val wgg: Long,
    private val wgm: Long,
    private val wgd: Long,
    private val wmg: Long,
    private val wmm: Long,
    private val wme: Long,
    private val wmd: Long,
    private val weg: Long,
    private val wem: Long,
    private val wee: Long,
    private val wed: Long,
) {
    enum class Role { GUARD, MIDDLE, EXIT }

    fun weight(rs: RouterStatus, role: Role): Long {
        val isExit = rs.isExit
        val isGuard = rs.isGuard
        val w = when (role) {
            Role.GUARD -> when {
                isGuard && isExit -> wgd
                isGuard -> wgg
                isExit -> weg
                else -> wgm
            }
            Role.MIDDLE -> when {
                isGuard && isExit -> wmd
                isGuard -> wmg
                isExit -> wme
                else -> wmm
            }
            Role.EXIT -> when {
                isGuard && isExit -> wed
                isExit -> wee
                isGuard -> wem
                else -> 0L
            }
        }
        val bw = rs.bandwidth.coerceAtLeast(1)
        val s = scale.coerceAtLeast(1)
        return (bw * w.coerceAtLeast(0)).coerceAtLeast(1) / s
    }

    companion object {
        fun fromParams(params: Map<String, Long>): BandwidthWeights {
            fun p(name: String, d: Long) = params[name] ?: d
            val scale = p("bwweightscale", 10_000)
            return BandwidthWeights(
                scale = scale,
                wgg = p("Wgg", scale),
                wgm = p("Wgm", scale),
                wgd = p("Wgd", 0),
                wmg = p("Wmg", scale),
                wmm = p("Wmm", scale),
                wme = p("Wme", scale),
                wmd = p("Wmd", 0),
                weg = p("Weg", 0),
                wem = p("Wem", scale),
                wee = p("Wee", scale),
                wed = p("Wed", 0),
            )
        }
    }
}
