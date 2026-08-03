package org.kotlintor.dir

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Microdescriptor consensus (flavor microdesc). Same as ns consensus but `r` lines
 * omit descriptor digest and include a following `m` digest line for the microdesc.
 */
object MicrodescConsensusParser {
    private val tsFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)

    fun parse(text: String): Consensus {
        var validAfter: Instant? = null
        var freshUntil: Instant? = null
        var validUntil: Instant? = null
        var sharedCurrent: ByteArray? = null
        var sharedPrevious: ByteArray? = null
        val params = linkedMapOf<String, Long>()
        val relays = mutableListOf<RouterStatus>()
        var cur: MutableRouter? = null

        fun flush() {
            cur?.let { relays += it.build() }
            cur = null
        }

        for (line in text.lineSequence()) {
            when {
                line.startsWith("valid-after ") ->
                    validAfter = Instant.from(tsFmt.parse(line.removePrefix("valid-after ").trim()))
                line.startsWith("fresh-until ") ->
                    freshUntil = Instant.from(tsFmt.parse(line.removePrefix("fresh-until ").trim()))
                line.startsWith("valid-until ") ->
                    validUntil = Instant.from(tsFmt.parse(line.removePrefix("valid-until ").trim()))
                line.startsWith("params ") -> {
                    for (tok in line.removePrefix("params ").split(' ')) {
                        val eq = tok.indexOf('=')
                        if (eq > 0) {
                            tok.substring(eq + 1).toLongOrNull()?.let {
                                params[tok.substring(0, eq)] = it
                            }
                        }
                    }
                }
                line.startsWith("shared-rand-current-value ") ->
                    sharedCurrent = parseSharedRand(line)
                line.startsWith("shared-rand-previous-value ") ->
                    sharedPrevious = parseSharedRand(line)
                line.startsWith("r ") -> {
                    flush()
                    val p = line.split(' ')
                    // r nickname identity publication-date publication-time ip orport dirport
                    cur = MutableRouter(
                        nickname = p[1],
                        identity = base64PadDecode(p[2]).also {
                            require(it.size == 20) { "identity must be 20 bytes" }
                        },
                        digest = ByteArray(20),
                        publication = Instant.from(tsFmt.parse("${p[3]} ${p[4]}")),
                        ip = p[5],
                        orPort = p[6].toInt(),
                        dirPort = p[7].toInt(),
                    )
                }
                line.startsWith("m ") -> cur?.microDigestB64 = line.removePrefix("m ").trim()
                line.startsWith("s ") -> cur?.flags = line.removePrefix("s ").split(' ').filter { it.isNotEmpty() }.toSet()
                line.startsWith("v ") -> cur?.version = line.removePrefix("v ").trim()
                line.startsWith("pr ") -> {
                    cur?.proto = line.removePrefix("pr ").split(' ')
                        .mapNotNull {
                            val i = it.indexOf('=')
                            if (i < 0) null else it.substring(0, i) to it.substring(i + 1)
                        }.toMap()
                }
                line.startsWith("w ") -> {
                    val bw = line.split(' ').firstOrNull { it.startsWith("Bandwidth=") }
                        ?.substringAfter('=')?.toLongOrNull()
                    if (bw != null) cur?.bandwidth = bw
                }
                line.startsWith("directory-footer") -> flush()
            }
        }
        flush()
        return Consensus(
            validAfter = requireNotNull(validAfter),
            freshUntil = requireNotNull(freshUntil),
            validUntil = requireNotNull(validUntil),
            relays = relays,
            raw = text,
            sharedRandCurrent = sharedCurrent,
            sharedRandPrevious = sharedPrevious,
            params = params,
        )
    }

    private fun parseSharedRand(line: String): ByteArray? {
        val parts = line.split(' ')
        if (parts.size < 3) return null
        return base64PadDecode(parts[2])
    }

    private fun base64PadDecode(s: String): ByteArray {
        var b64 = s
        while (b64.length % 4 != 0) b64 += "="
        return java.util.Base64.getDecoder().decode(b64)
    }

    private class MutableRouter(
        val nickname: String,
        val identity: ByteArray,
        val digest: ByteArray,
        val publication: Instant,
        val ip: String,
        val orPort: Int,
        val dirPort: Int,
        var flags: Set<String> = emptySet(),
        var version: String? = null,
        var proto: Map<String, String> = emptyMap(),
        var bandwidth: Long = 0,
        var microDigestB64: String? = null,
    ) {
        fun build() = RouterStatus(
            nickname, identity, digest, publication, ip, orPort, dirPort,
            flags, version, proto, bandwidth,
        )
    }
}
