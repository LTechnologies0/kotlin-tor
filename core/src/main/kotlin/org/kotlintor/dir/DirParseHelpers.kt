package org.kotlintor.dir

import org.kotlintor.relay.ExitPolicy
import java.util.concurrent.ConcurrentHashMap

/**
 * Shared directory-document parse helpers (C Tor `dirparse/parsecommon.c`,
 * `policy_parse.c`, `unparseable.c`, `sigcommon.c`, `signing.c`).
 *
 * Inventory: `L1:feature/dirparse/parsecommon.c`, `policy_parse.c`,
 * `unparseable.c`, `sigcommon.c`, `signing.c`, `authcert_parse.c`
 */
object DirParseCommon {
    /** Split a dir-spec document into keyword → multi-line value map (first wins). */
    fun keywordMap(document: String): Map<String, String> {
        val out = linkedMapOf<String, String>()
        val lines = document.replace("\r\n", "\n").split('\n')
        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            if (line.isEmpty() || line.startsWith("-----BEGIN")) {
                i++
                continue
            }
            val sp = line.indexOf(' ')
            val key = if (sp < 0) line else line.substring(0, sp)
            val rest = if (sp < 0) "" else line.substring(sp + 1)
            if (key !in out) out[key] = rest
            i++
        }
        return out
    }

    /** All values for a repeated keyword (C Tor tokenize multi). */
    fun keywordAll(document: String, key: String): List<String> {
        val out = ArrayList<String>()
        for (line in document.replace("\r\n", "\n").lineSequence()) {
            if (line.startsWith("$key ")) out += line.removePrefix("$key ").trim()
            else if (line == key) out += ""
        }
        return out
    }

    fun requireKeyword(document: String, key: String): String =
        keywordMap(document)[key] ?: error("missing keyword $key")

    fun hasKeyword(document: String, key: String): Boolean = key in keywordMap(document)
}

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

/**
 * Dump bin for documents that fail to parse (C Tor `unparseable.c`).
 */
object UnparseableDump {
    private val dumps = ConcurrentHashMap<String, String>()

    fun note(tag: String, body: String) {
        dumps[tag] = body.take(64_000)
    }

    fun get(tag: String): String? = dumps[tag]

    fun clear() = dumps.clear()

    fun size(): Int = dumps.size

    fun tags(): Set<String> = dumps.keys.toSet()
}

/**
 * Authcert parse entry (delegates to [AuthorityCert]).
 * Inventory: `L1:feature/dirparse/authcert_parse.c`
 */
object AuthCertParse {
    fun parse(document: String): AuthorityCert.Parsed = AuthorityCert.parse(document)

    fun verify(parsed: AuthorityCert.Parsed): Boolean = AuthorityCert.verify(parsed)

    fun tryParse(document: String): AuthorityCert.Parsed? =
        runCatching { parse(document) }.getOrNull()
}

/**
 * Directory signature helpers (C Tor `sigcommon` / `signing`).
 * Inventory: `L1:feature/dirparse/sigcommon.c`, `signing.c`
 */
object DirSigning {
    fun sha1DigestHex(document: String): String =
        org.kotlintor.crypto.Digests.sha1(document.toByteArray(Charsets.US_ASCII))
            .joinToString("") { "%02X".format(it.toInt() and 0xff) }

    fun findSignatureBlock(document: String, begin: String = "-----BEGIN SIGNATURE-----"): String? {
        val start = document.indexOf(begin)
        if (start < 0) return null
        val endMark = begin.replace("BEGIN", "END")
        val end = document.indexOf(endMark, start)
        if (end < 0) return null
        return document.substring(start, end + endMark.length)
    }

    fun stripSignatures(document: String): String {
        val idx = document.indexOf("-----BEGIN SIGNATURE-----")
        return if (idx < 0) document else document.substring(0, idx)
    }
}
