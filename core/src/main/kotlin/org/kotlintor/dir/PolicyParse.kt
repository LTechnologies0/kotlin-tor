package org.kotlintor.dir

import org.kotlintor.relay.ExitPolicy

/**
 * Exit policy line parse (C Tor `policy_parse.c`).
 *
 * Inventory: `L1:feature/dirparse/policy_parse.c`
 */
object PolicyParse {
    /** Parse ExitPolicy-style lines into [ExitPolicy]. */
    fun parseExitPolicyLines(lines: List<String>): ExitPolicy =
        if (lines.isEmpty()) ExitPolicy.rejectAll()
        else ExitPolicy.fromTorrcLines(lines)

    fun parseSingle(line: String): ExitPolicy = parseExitPolicyLines(listOf(line))

    /** Reject malformed policy lines rather than silently accepting. */
    fun isWellFormed(line: String): Boolean {
        val t = line.trim()
        if (t.isEmpty()) return false
        val parts = t.split(Regex("\\s+"))
        if (parts.size < 2) return false
        val verb = parts[0].lowercase()
        if (verb != "accept" && verb != "reject") return false
        return parts[1].contains(':') || parts[1] == "*"
    }
}

