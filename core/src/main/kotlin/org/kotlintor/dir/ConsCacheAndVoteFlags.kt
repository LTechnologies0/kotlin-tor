package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.util.toHex
import java.util.concurrent.ConcurrentHashMap

/**
 * Consensus / diff document cache (C Tor `conscache.c` lite).
 */
class ConsCache(private val maxEntries: Int = 64) {
    data class Entry(
        val digestHex: String,
        val body: String,
        val storedAtEpochSec: Long,
    )

    private val byDigest = LinkedHashMap<String, Entry>(16, 0.75f, true)

    fun put(body: String, nowEpochSec: Long = System.currentTimeMillis() / 1000): Entry {
        val dig = Digests.sha3_256(body.toByteArray(Charsets.US_ASCII)).toHex().lowercase()
        val e = Entry(dig, body, nowEpochSec)
        synchronized(byDigest) {
            byDigest[dig] = e
            while (byDigest.size > maxEntries) {
                val eldest = byDigest.entries.iterator()
                if (eldest.hasNext()) {
                    eldest.next()
                    eldest.remove()
                } else break
            }
        }
        return e
    }

    fun get(digestHex: String): Entry? = synchronized(byDigest) {
        byDigest[digestHex.lowercase()]
    }

    fun getBySha3Prefix(prefixHex: String): Entry? = synchronized(byDigest) {
        val p = prefixHex.lowercase()
        byDigest.values.firstOrNull { it.digestHex.startsWith(p) }
    }

    fun size(): Int = synchronized(byDigest) { byDigest.size }

    fun clear() = synchronized(byDigest) { byDigest.clear() }
}

/**
 * Fingerprint pair (RSA + Ed25519) helper (C Tor `fp_pair.c`).
 */
data class FpPair(val rsaIdHex: String, val ed25519Hex: String) {
    init {
        require(rsaIdHex.length == 40)
        require(ed25519Hex.length == 64)
    }

    companion object {
        fun of(rsa: ByteArray, ed: ByteArray): FpPair {
            require(rsa.size == 20 && ed.size == 32)
            return FpPair(rsa.toHex().lowercase(), ed.toHex().lowercase())
        }
    }
}

/**
 * Vote flag assignment heuristics (C Tor `voteflags.c` lite).
 *
 * Produces the flag set an authority would advertise for a relay given
 * measured bandwidth, uptime, and reachability.
 */
object VoteFlags {
    data class Input(
        val isAuthority: Boolean = false,
        val isRunning: Boolean = true,
        val isValid: Boolean = true,
        val isExit: Boolean = false,
        val isBadExit: Boolean = false,
        val bandwidthKb: Int = 0,
        val weightedBwKb: Int = 0,
        val uptimeSec: Long = 0,
        val reachable: Boolean = true,
        val supportsHsDir: Boolean = false,
        val hasEdConsensus: Boolean = true,
        val stableUptimeSec: Long = 7 * 24 * 3600,
        val guardBwThresholdKb: Int = 2_000,
        val fastBwThresholdKb: Int = 100,
    )

    fun assign(input: Input): Set<String> {
        val flags = LinkedHashSet<String>()
        if (input.isAuthority) flags += "Authority"
        if (input.isValid) flags += "Valid"
        if (input.isRunning && input.reachable) flags += "Running"
        if (input.isExit) flags += "Exit"
        if (input.isBadExit) flags += "BadExit"
        if (input.bandwidthKb >= input.fastBwThresholdKb) flags += "Fast"
        if (input.uptimeSec >= input.stableUptimeSec) flags += "Stable"
        if ("Fast" in flags && "Stable" in flags &&
            input.weightedBwKb >= input.guardBwThresholdKb
        ) {
            flags += "Guard"
        }
        if (input.supportsHsDir && "Fast" in flags) flags += "HSDir"
        if (!input.hasEdConsensus) flags += "NoEdConsensus"
        flags += "V2Dir"
        return flags
    }
}

/**
 * Port prediction for circuit prebuild (C Tor `predict_ports.c` lite).
 */
object PredictPorts {
    private val counts = ConcurrentHashMap<Int, Int>()

    fun noteUse(port: Int) {
        if (port in 1..65535) counts.merge(port, 1, Int::plus)
    }

    fun predicted(limit: Int = 8): List<Int> =
        counts.entries.sortedByDescending { it.value }.take(limit).map { it.key }

    fun clear() = counts.clear()
}
