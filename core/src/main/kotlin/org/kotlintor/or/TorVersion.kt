package org.kotlintor.or

/** C Tor `tor_version_t`. */
data class TorVersion(
    val major: Int,
    val minor: Int,
    val micro: Int,
    val status: String = "stable",
) {
    override fun toString(): String = "$major.$minor.$micro-$status"
    companion object {
        fun parse(s: String): TorVersion? {
            val m = Regex("""(\d+)\.(\d+)\.(\d+)(?:-(\w+))?""").matchEntire(s.trim()) ?: return null
            return TorVersion(
                m.groupValues[1].toInt(),
                m.groupValues[2].toInt(),
                m.groupValues[3].toInt(),
                m.groupValues[4].ifEmpty { "stable" },
            )
        }
    }
}
