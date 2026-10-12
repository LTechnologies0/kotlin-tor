package org.kotlintor.dir

/**
 * Microdescriptor `p accept|reject PortList` (dir-spec). Address is implied `*`.
 */
object MicrodescExitPolicy {
    fun allowsPort(summary: String?, port: Int): Boolean {
        if (summary.isNullOrBlank()) return false
        if (port !in 1..65535) return false
        val t = summary.trim()
        val verb = t.substringBefore(' ').lowercase()
        val list = t.substringAfter(' ', missingDelimiterValue = "").trim()
        if (verb != "accept" && verb != "reject") return false
        val hit = portInList(list, port)
        return if (verb == "accept") hit else !hit
    }

    fun parseSummary(line: String): String? {
        val t = line.trim()
        val body = when {
            t.startsWith("p ") -> t.removePrefix("p ").trim()
            else -> t
        }
        if (body.startsWith("accept ") || body.startsWith("reject ")) return body
        return null
    }

    private fun portInList(list: String, port: Int): Boolean {
        if (list == "*" || list == "1-65535") return true
        for (tok in list.split(',')) {
            val p = tok.trim()
            if (p.isEmpty()) continue
            if ('-' in p) {
                val a = p.substringBefore('-').toIntOrNull() ?: continue
                val b = p.substringAfter('-').toIntOrNull() ?: continue
                if (port in a..b) return true
            } else if (p.toIntOrNull() == port) {
                return true
            }
        }
        return false
    }
}
