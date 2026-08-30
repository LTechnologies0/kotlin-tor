package org.kotlintor.dir

/**
 * RecommendedPackages line validation (C Tor `recommend_pkg.c`).
 *
 * Grammar: `PACKAGENAME VERSION URL DIGESTTYPE=DIGESTVAL…`

 * Inventory: `L1:feature/dirauth/recommend_pkg.c`
 */
object RecommendPkg {
    data class Package(
        val name: String,
        val version: String,
        val url: String,
        val digests: Map<String, String>,
    )

    fun validate(line: String): Boolean = parse(line) != null

    /** C Tor `validate_recommended_package_line`. */
    fun validateRecommendedPackageLine(line: String): Boolean = validate(line)

    fun parse(line: String): Package? {
        val parts = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (parts.size < 4) return null
        val digests = LinkedHashMap<String, String>()
        for (i in 3 until parts.size) {
            val eq = parts[i].indexOf('=')
            if (eq <= 0 || eq == parts[i].lastIndex) return null
            if (parts[i].indexOf('=', eq + 1) >= 0) return null
            digests[parts[i].substring(0, eq)] = parts[i].substring(eq + 1)
        }
        if (digests.isEmpty()) return null
        return Package(parts[0], parts[1], parts[2], digests)
    }
}
