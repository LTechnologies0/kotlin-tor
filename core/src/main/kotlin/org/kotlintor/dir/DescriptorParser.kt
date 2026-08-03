package org.kotlintor.dir

data class RelayDescriptor(
    val fingerprintHex: String,
    val ntorOnionKey: ByteArray,
    val ed25519Identity: ByteArray?,
    val raw: String,
)

object DescriptorParser {
    fun parseNtorOnionKey(document: String): ByteArray? {
        for (line in document.lineSequence()) {
            if (line.startsWith("ntor-onion-key ")) {
                return decode32(line.removePrefix("ntor-onion-key ").trim())
            }
        }
        return null
    }

    fun parseEd25519Identity(document: String): ByteArray? {
        for (line in document.lineSequence()) {
            if (line.startsWith("master-key-ed25519 ")) {
                return decode32(line.removePrefix("master-key-ed25519 ").trim())
            }
        }
        return null
    }

    /**
     * Parse `family` lines (nicknames and `$FINGERPRINT` tokens).
     * Returns uppercase fingerprint hex when `$` prefixed; nicknames otherwise.
     */
    fun parseFamily(document: String): Set<String> {
        val out = mutableSetOf<String>()
        for (line in document.lineSequence()) {
            if (!line.startsWith("family ")) continue
            for (tok in line.removePrefix("family ").trim().split(Regex("\\s+"))) {
                val t = tok.trim()
                if (t.isEmpty()) continue
                out += if (t.startsWith("$")) t.removePrefix("$").uppercase() else t
            }
        }
        return out
    }

    fun parse(document: String, fallbackFingerprintHex: String? = null): RelayDescriptor? {
        val ntor = parseNtorOnionKey(document) ?: return null
        var fp = fallbackFingerprintHex?.uppercase()
        for (line in document.lineSequence()) {
            if (line.startsWith("fingerprint ")) {
                fp = line.removePrefix("fingerprint ").replace(" ", "").uppercase()
            }
        }
        return RelayDescriptor(
            fingerprintHex = fp ?: return null,
            ntorOnionKey = ntor,
            ed25519Identity = parseEd25519Identity(document),
            raw = document,
        )
    }

    private fun decode32(b64raw: String): ByteArray? {
        var b64 = b64raw.trim()
        while (b64.length % 4 != 0) b64 += "="
        val key = runCatching { java.util.Base64.getDecoder().decode(b64) }.getOrNull() ?: return null
        return if (key.size == 32) key else null
    }
}
