package org.kotlintor.dir

/**
 * Tor software version parse/compare (C Tor `versions.c`).
 *
 * Inventory: `L1:core/or/versions.c`
 *
 * Note: link-protocol VERSIONS cells live elsewhere; this module is the
 * directory/version-status path (`tor_version_parse`, `tor_version_is_obsolete`).
 */
object Versions {
    enum class Status {
        RECOMMENDED,
        OLD,
        NEW,
        NEW_IN_SERIES,
        UNRECOMMENDED,
        EMPTY,
        UNKNOWN,
    }

    data class TorVersion(
        val major: Int,
        val minor: Int,
        val micro: Int,
        val patchLevel: Int = 0,
        val statusTag: String = "stable",
    ) : Comparable<TorVersion> {
        override fun compareTo(other: TorVersion): Int {
            var c = major.compareTo(other.major)
            if (c != 0) return c
            c = minor.compareTo(other.minor)
            if (c != 0) return c
            c = micro.compareTo(other.micro)
            if (c != 0) return c
            return patchLevel.compareTo(other.patchLevel)
        }

        fun sameSeries(other: TorVersion): Boolean =
            major == other.major && minor == other.minor && micro == other.micro

        override fun toString(): String {
            val base = if (patchLevel > 0) "$major.$minor.$micro.$patchLevel" else "$major.$minor.$micro"
            return if (statusTag.isEmpty() || statusTag == "stable") "$base-stable" else "$base-$statusTag"
        }
    }

    private val VER_RE =
        Regex("""(?i)^(?:Tor\s+)?(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([A-Za-z0-9]+))?$""")

    /** C Tor `tor_version_parse`. */
    fun parse(s: String): TorVersion? {
        val m = VER_RE.matchEntire(s.trim()) ?: return null
        return TorVersion(
            major = m.groupValues[1].toInt(),
            minor = m.groupValues[2].toInt(),
            micro = m.groupValues[3].ifEmpty { "0" }.toInt(),
            patchLevel = m.groupValues[4].ifEmpty { "0" }.toInt(),
            statusTag = m.groupValues[5].ifEmpty { "stable" },
        )
    }

    /** C Tor `tor_version_compare`. */
    fun compare(a: TorVersion, b: TorVersion): Int = a.compareTo(b)

    /** C Tor `tor_version_same_series`. */
    fun sameSeries(a: TorVersion, b: TorVersion): Boolean = a.sameSeries(b)

    /**
     * C Tor `tor_version_is_obsolete` (simplified).
     * Returns [Status.RECOMMENDED] if [myVersion] appears in the comma list;
     * [Status.EMPTY] if the list is blank; otherwise OLD/NEW/NEW_IN_SERIES/UNRECOMMENDED.
     */
    fun isObsolete(myVersion: String, versionList: String): Status {
        val mine = parse(myVersion) ?: return Status.UNKNOWN
        val raw = versionList.trim()
        if (raw.isEmpty()) return Status.EMPTY
        val parsed = raw.split(',')
            .map { it.trim().removePrefix("Tor ").trim() }
            .mapNotNull { parse(it) }
        if (parsed.isEmpty()) return Status.EMPTY
        if (parsed.any { it == mine || (it.major == mine.major && it.minor == mine.minor &&
                it.micro == mine.micro && it.patchLevel == mine.patchLevel)
        }) {
            return Status.RECOMMENDED
        }
        val newer = parsed.any { it > mine }
        val older = parsed.any { it < mine }
        val series = parsed.filter { it.sameSeries(mine) }
        return when {
            !newer && older -> Status.NEW
            newer && !older -> Status.OLD
            series.isNotEmpty() && series.none { it > mine } && newer -> Status.NEW_IN_SERIES
            else -> Status.UNRECOMMENDED
        }
    }

    /** C Tor `tor_version_as_new_as` — true if platform ≥ cutoff. */
    fun asNewAs(platform: String, cutoff: String): Boolean {
        val p = parse(platform) ?: return false
        val c = parse(cutoff) ?: return false
        return p >= c
    }

    private val protoverSummaryCache = java.util.concurrent.ConcurrentHashMap<String, String>()

    /** C Tor `protover_summary_cache_free_all`. */
    fun protoverSummaryCacheFreeAll() = protoverSummaryCache.clear()

    /** C Tor `summarize_protover_flags` — compact flag summary. */
    fun summarizeProtoverFlags(list: String): String {
        val cached = protoverSummaryCache[list]
        if (cached != null) return cached
        val map = Protover.parseProtocolList(list)
        val summary = map.entries.joinToString(",") { (k, v) -> "$k=$v" }
        protoverSummaryCache[list] = summary
        return summary
    }

    /** C Tor `sort_version_list`. */
    fun sortVersionList(versions: List<String>): List<String> =
        versions.mapNotNull { v -> parse(v)?.let { it to v } }
            .sortedBy { it.first }
            .map { it.second }

    /** C Tor `tor_get_approx_release_date` — stub epoch for unknown. */
    fun torGetApproxReleaseDate(version: String): Long {
        val v = parse(version) ?: return 0L
        // Rough calendar mapping for major.minor series (not exact).
        return when {
            v.major >= 0 && v.minor >= 4 -> 1_700_000_000L
            else -> 1_500_000_000L
        }
    }

    fun torVersionParse(s: String): TorVersion? = parse(s)
    fun torVersionCompare(a: TorVersion, b: TorVersion): Int = compare(a, b)
    fun torVersionSameSeries(a: TorVersion, b: TorVersion): Boolean = sameSeries(a, b)
    fun torVersionIsObsolete(myVersion: String, versionList: String): Status =
        isObsolete(myVersion, versionList)
    fun torVersionAsNewAs(platform: String, cutoff: String): Boolean = asNewAs(platform, cutoff)
    fun torVersionParsePlatform(platform: String): TorVersion? =
        parse(platform.removePrefix("Tor ").trim())
}
