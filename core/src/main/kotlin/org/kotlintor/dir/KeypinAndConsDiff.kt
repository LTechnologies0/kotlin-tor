package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.util.toHex
import java.util.concurrent.ConcurrentHashMap

/**
 * RSA↔Ed25519 identity keypin journal (C Tor `keypin.c`).
 *
 * Ensures a given RSA identity fingerprint maps to at most one Ed25519 id
 * (and vice versa) across descriptor votes. Supports persistent journal I/O.
 *
 * Inventory: `L1:feature/dirauth/keypin.c`
 */
object Keypin {
    enum class Result { OK, CONFLICT, ADDED, REPLACED }

    data class Entry(val rsaIdHex: String, val ed25519Hex: String)

    class Journal {
        private val byRsa = ConcurrentHashMap<String, String>()
        private val byEd = ConcurrentHashMap<String, String>()

        fun check(rsaId: ByteArray, ed25519: ByteArray): Result {
            require(rsaId.size == 20)
            require(ed25519.size == 32)
            val r = rsaId.toHex().lowercase()
            val e = ed25519.toHex().lowercase()
            val existingEd = byRsa[r]
            val existingRsa = byEd[e]
            if (existingEd == null && existingRsa == null) return Result.OK
            if (existingEd == e && existingRsa == r) return Result.OK
            return Result.CONFLICT
        }

        fun checkAndAdd(rsaId: ByteArray, ed25519: ByteArray, replace: Boolean = false): Result {
            val r = rsaId.toHex().lowercase()
            val e = ed25519.toHex().lowercase()
            when (check(rsaId, ed25519)) {
                Result.OK -> {
                    if (byRsa.containsKey(r) && byRsa[r] == e) return Result.OK
                    byRsa[r] = e
                    byEd[e] = r
                    return Result.ADDED
                }
                Result.CONFLICT -> {
                    if (!replace) return Result.CONFLICT
                    byRsa[r]?.let { byEd.remove(it) }
                    byEd[e]?.let { byRsa.remove(it) }
                    byRsa[r] = e
                    byEd[e] = r
                    return Result.REPLACED
                }
                else -> return Result.CONFLICT
            }
        }

        fun checkLoneRsa(rsaId: ByteArray): Boolean {
            val r = rsaId.toHex().lowercase()
            return !byRsa.containsKey(r)
        }

        fun verifyAll(): Boolean {
            if (byRsa.size != byEd.size) return false
            for ((r, e) in byRsa) {
                if (byEd[e] != r) return false
            }
            return true
        }

        fun entries(): List<Entry> = byRsa.map { Entry(it.key, it.value) }

        fun formatJournal(): String = buildString {
            appendLine("keypin-journal-version 1")
            for (e in entries().sortedBy { it.rsaIdHex }) {
                appendLine("rsa-ed ${e.rsaIdHex} ${e.ed25519Hex}")
            }
        }

        fun loadJournal(text: String) {
            for (line in text.lineSequence()) {
                val p = line.trim().split(Regex("\\s+"))
                if (p.size >= 3 && p[0] == "rsa-ed") {
                    byRsa[p[1].lowercase()] = p[2].lowercase()
                    byEd[p[2].lowercase()] = p[1].lowercase()
                }
            }
        }

        fun saveTo(path: java.nio.file.Path) {
            java.nio.file.Files.createDirectories(path.parent)
            java.nio.file.Files.writeString(path, formatJournal())
        }

        fun loadFrom(path: java.nio.file.Path): Boolean {
            if (!java.nio.file.Files.isRegularFile(path)) return false
            loadJournal(java.nio.file.Files.readString(path))
            return verifyAll()
        }

        fun clear() {
            byRsa.clear()
            byEd.clear()
        }

        fun size(): Int = byRsa.size
    }
}

/**
 * Consensus diff (C Tor `consdiff.c`) — ed-style line patch for networkstatus.
 *
 * Format (dir-spec):
 * ```
 * network-status-diff-version 1
 * hash <sha3-256-old> <sha3-256-new>
 * ... ed commands ...
 * ```
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
                cmd.isBlank() -> Unit
                else -> error("unsupported consdiff command: $cmd")
            }
        }
        val out = body.joinToString("\n", postfix = "\n")
        val actualNew = sha3Hex(out)
        require(actualNew == expectNew) {
            "consdiff result hash mismatch: have $actualNew expect $expectNew"
        }
        return out
    }
}
