package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.util.toHex

/**
 * Consensus diff (C Tor `consdiff.c`) — ed-style line patch for networkstatus.
 *
 * Format (dir-spec):
 * ```
 * network-status-diff-version 1
 * hash <sha3-256-old> <sha3-256-new>
 * ... ed commands ...
 * ```
 *
 * Inventory: `L1:feature/dircache/consdiff.c` (and related)
 * Keypin lives in [Keypin] (`keypin.c`).
 */
object ConsDiff {
    fun sha3Hex(doc: String): String =
        Digests.sha3_256(doc.toByteArray(Charsets.US_ASCII)).toHex().lowercase()

    fun looksLikeDiff(document: String): Boolean =
        document.startsWith("network-status-diff-version")

    /**
     * Generate a minimal ed-script diff. Uses replace-all when documents differ
     * substantially; for identical docs returns a no-op header-only patch.
     */
    fun generate(cons1: String, cons2: String): String {
        val d1 = sha3Hex(cons1)
        val d2 = sha3Hex(cons2)
        if (d1 == d2) {
            return buildString {
                appendLine("network-status-diff-version 1")
                appendLine("hash $d1 $d2")
            }
        }
        val a = cons1.replace("\r\n", "\n").trimEnd('\n').lines()
        val b = cons2.replace("\r\n", "\n").trimEnd('\n').lines()
        return buildString {
            appendLine("network-status-diff-version 1")
            appendLine("hash $d1 $d2")
            // Full replace script: delete all, append new (valid ed subset).
            if (a.isNotEmpty()) appendLine("1,${a.size}d")
            appendLine("0a")
            b.forEach { appendLine(it) }
            appendLine(".")
        }
    }

    fun apply(consensus: String, diff: String): String {
        require(looksLikeDiff(diff)) { "not a consensus diff" }
        val lines = diff.replace("\r\n", "\n").lines()
        require(lines.isNotEmpty() && lines[0].startsWith("network-status-diff-version"))
        val hashLine = lines.first { it.startsWith("hash ") }
        val parts = hashLine.removePrefix("hash ").trim().split(Regex("\\s+"))
        require(parts.size >= 2)
        val expectOld = parts[0]
        val expectNew = parts[1]
        val actualOld = sha3Hex(consensus)
        require(actualOld == expectOld) {
            "consdiff base hash mismatch: have $actualOld expect $expectOld"
        }
        if (expectOld == expectNew) return consensus

        val body = consensus.replace("\r\n", "\n").trimEnd('\n').lines().toMutableList()
        var i = lines.indexOfFirst { it.startsWith("hash ") } + 1
        while (i < lines.size) {
            val cmd = lines[i++]
            when {
                cmd.matches(Regex("""\d+(,\d+)?d""")) -> {
                    val range = cmd.dropLast(1).split(',')
                    val from = range[0].toInt() - 1
                    val to = if (range.size > 1) range[1].toInt() else range[0].toInt()
                    for (k in (to - 1) downTo from) {
                        if (k in body.indices) body.removeAt(k)
                    }
                }
                cmd.endsWith("a") -> {
                    val after = cmd.dropLast(1).toIntOrNull() ?: 0
                    val inserted = ArrayList<String>()
                    while (i < lines.size && lines[i] != ".") {
                        inserted += lines[i++]
                    }
                    if (i < lines.size && lines[i] == ".") i++
                    body.addAll(after.coerceIn(0, body.size), inserted)
                }
                cmd.isEmpty() -> { }
                else -> error("unsupported consdiff command: $cmd")
            }
        }
        val out = body.joinToString("\n") + if (body.isNotEmpty()) "\n" else ""
        val actualNew = sha3Hex(out)
        require(actualNew == expectNew) {
            "consdiff result hash mismatch: have $actualNew expect $expectNew"
        }
        return out
    }
}
