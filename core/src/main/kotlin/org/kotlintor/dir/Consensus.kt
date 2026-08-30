package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.util.hexToBytes
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

data class Consensus(
    val validAfter: Instant,
    val freshUntil: Instant,
    val validUntil: Instant,
    val relays: List<RouterStatus>,
    val raw: String,
    val sharedRandCurrent: ByteArray? = null,
    val sharedRandPrevious: ByteArray? = null,
    val params: Map<String, Long> = emptyMap(),
) {
    fun isValidAt(now: Instant = Instant.now()): Boolean =
        !now.isBefore(validAfter) && now.isBefore(validUntil)

    fun param(name: String, default: Long): Long = params[name] ?: default
}

data class RouterStatus(
    val nickname: String,
    val identity: ByteArray,
    val digest: ByteArray,
    val publication: Instant,
    val ip: String,
    val orPort: Int,
    val dirPort: Int,
    val flags: Set<String>,
    val version: String?,
    val proto: Map<String, String>,
    val bandwidth: Long,
    val ntorOnionKey: ByteArray? = null,
    val ed25519Identity: ByteArray? = null,
) {
    val isGuard get() = "Guard" in flags
    val isExit get() = "Exit" in flags && "BadExit" !in flags
    val isBadExit get() = "BadExit" in flags
    val isFast get() = "Fast" in flags
    val isStable get() = "Stable" in flags
    val isRunning get() = "Running" in flags
    val isHsDir get() = "HSDir" in flags
    /** Cached; avoid recomputing in hot loops (path / HSDir selection). */
    val fingerprintHex: String = identity.joinToString("") { b ->
        val v = b.toInt() and 0xff
        val hex = "0123456789ABCDEF"
        "${hex[v ushr 4]}${hex[v and 15]}"
    }

    /** True if consensus `pr` line advertises subprotocol [name] version [version]. */
    fun supportsProto(name: String, version: Int): Boolean {
        val raw = proto[name] ?: return false
        for (part in raw.split(',')) {
            val t = part.trim()
            if (t.contains('-')) {
                val a = t.substringBefore('-').toIntOrNull() ?: continue
                val b = t.substringAfter('-').toIntOrNull() ?: continue
                if (version in a..b) return true
            } else if (t.toIntOrNull() == version) {
                return true
            }
        }
        return false
    }

    /** Relay=4 advertises ntor-v3 (CREATE2 HTYPE=3). */
    fun supportsNtorV3(): Boolean = supportsProto("Relay", 4)

    /** Relay=5: SUBPROTO_REQUEST extension (RELAY_NEGOTIATE_SUBPROTO). */
    fun supportsSubprotoNegotiate(): Boolean = supportsProto("Relay", 5)

    /** Relay=6: Counter Galois Onion (Prop359 RELAY_CRYPT_CGO). */
    fun supportsCgo(): Boolean = supportsProto("Relay", 6)

    /** FlowCtrl=2 advertises prop324 congestion control. */
    fun supportsFlowCtrl2(): Boolean = supportsProto("FlowCtrl", 2)

    /** Conflux=1 (prop329). */
    val supportsConflux: Boolean get() = supportsProto("Conflux", 1)

    override fun equals(other: Any?): Boolean =
        other is RouterStatus && identity.contentEquals(other.identity)

    override fun hashCode(): Int = identity.contentHashCode()
}

object ConsensusParser {
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
                    // r nickname identity digest publication-date publication-time ip orport dirport
                    cur = MutableRouter(
                        nickname = p[1],
                        identity = base64To20(p[2]),
                        digest = base64To20(p[3]),
                        publication = Instant.from(tsFmt.parse("${p[4]} ${p[5]}")),
                        ip = p[6],
                        orPort = p[7].toInt(),
                        dirPort = p[8].toInt(),
                    )
                }
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
                line.startsWith("id ed25519 ") -> {
                    val b64 = line.removePrefix("id ed25519 ").trim()
                    cur?.ed25519Identity = base64PadDecode(b64)
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
        // shared-rand-current-value NumReveals Value
        val parts = line.split(' ')
        if (parts.size < 3) return null
        return base64PadDecode(parts[2])
    }

    private fun base64To20(s: String): ByteArray {
        val decoded = base64PadDecode(s)
        require(decoded.size == 20) { "expected 20-byte digest, got ${decoded.size}" }
        return decoded
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
        var ed25519Identity: ByteArray? = null,
    ) {
        fun build() = RouterStatus(
            nickname, identity, digest, publication, ip, orPort, dirPort,
            flags, version, proto, bandwidth, ed25519Identity = ed25519Identity,
        )
    }
}

object MicrodescParser {
    fun parseOnionKey(microdesc: String): ByteArray? = DescriptorParser.parseNtorOnionKey(microdesc)

    fun splitDocuments(body: String): List<String> {
        val docs = mutableListOf<String>()
        val sb = StringBuilder()
        for (line in body.lineSequence()) {
            if (line.startsWith("onion-key") && sb.isNotEmpty()) {
                docs += sb.toString()
                sb.clear()
            }
            sb.appendLine(line)
        }
        if (sb.isNotEmpty()) docs += sb.toString()
        return docs
    }
}

fun fingerprintFromHex(hex: String): ByteArray = hexToBytes(hex.replace(" ", ""))

fun routerIdentityDigest(identity: ByteArray): String =
    Digests.sha1(identity).joinToString("") { "%02X".format(it) }
