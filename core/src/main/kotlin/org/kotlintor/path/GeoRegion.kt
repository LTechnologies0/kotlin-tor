package org.kotlintor.path

/**
 * Client-local continent mapping from ISO 3166-1 alpha-2 country codes.
 *
 * Tor GeoIP only provides country codes; "region" diversity uses this table.
 * Does not affect consensus documents or CREATE/EXTEND wire formats.
 */
object GeoRegion {
    enum class Continent {
        AF,
        AN,
        AS,
        EU,
        NA,
        OC,
        SA,
        UNKNOWN,
    }

    /** Country code (lowercase) → continent. Unlisted codes → [Continent.UNKNOWN]. */
    fun continentOf(countryCode: String?): Continent {
        if (countryCode.isNullOrBlank()) return Continent.UNKNOWN
        val cc = countryCode.trim().lowercase()
        return COUNTRY_TO_CONTINENT[cc] ?: Continent.UNKNOWN
    }

    private val COUNTRY_TO_CONTINENT: Map<String, Continent> = buildMap {
        fun putAll(c: Continent, vararg codes: String) {
            for (code in codes) put(code, c)
        }
        putAll(
            Continent.EU,
            "ad", "al", "at", "ax", "ba", "be", "bg", "by", "ch", "cy", "cz", "de", "dk",
            "ee", "es", "fi", "fo", "fr", "gb", "gg", "gi", "gr", "hr", "hu", "ie", "im",
            "is", "it", "je", "li", "lt", "lu", "lv", "mc", "md", "me", "mk", "mt", "nl",
            "no", "pl", "pt", "ro", "rs", "ru", "se", "si", "sj", "sk", "sm", "ua", "uk",
            "va", "xk",
        )
        putAll(
            Continent.NA,
            "ag", "ai", "aw", "bb", "bl", "bm", "bq", "bs", "bz", "ca", "cr", "cu", "cw",
            "dm", "do", "gd", "gl", "gp", "gt", "hn", "ht", "jm", "kn", "ky", "lc", "mf",
            "mq", "ms", "mx", "ni", "pa", "pm", "pr", "sv", "sx", "tc", "tt", "us", "vc",
            "vg", "vi",
        )
        putAll(
            Continent.SA,
            "ar", "bo", "br", "cl", "co", "ec", "fk", "gf", "gy", "pe", "py", "sr", "uy", "ve",
        )
        putAll(
            Continent.AF,
            "ao", "bf", "bi", "bj", "bw", "cd", "cf", "cg", "ci", "cm", "cv", "dj", "dz",
            "eg", "eh", "er", "et", "ga", "gh", "gm", "gn", "gq", "gw", "ke", "km", "lr",
            "ls", "ly", "ma", "mg", "ml", "mr", "mu", "mw", "mz", "na", "ne", "ng", "re",
            "rw", "sc", "sd", "sh", "sl", "sn", "so", "ss", "st", "sz", "td", "tg", "tn",
            "tz", "ug", "yt", "za", "zm", "zw",
        )
        putAll(
            Continent.AS,
            "ae", "af", "am", "az", "bd", "bh", "bn", "bt", "cn", "ge", "hk", "id", "il",
            "in", "iq", "ir", "jo", "jp", "kg", "kh", "kp", "kr", "kw", "kz", "la", "lb",
            "lk", "mm", "mn", "mo", "mv", "my", "np", "om", "ph", "pk", "ps", "qa", "sa",
            "sg", "sy", "th", "tj", "tl", "tm", "tr", "tw", "uz", "vn", "ye",
        )
        putAll(
            Continent.OC,
            "as", "au", "ck", "fj", "fm", "gu", "ki", "mh", "mp", "nc", "nf", "nr", "nu",
            "nz", "pf", "pg", "pn", "pw", "sb", "tk", "to", "tv", "um", "vu", "wf", "ws",
        )
        putAll(Continent.AN, "aq", "bv", "gs", "hm", "tf")
    }
}
