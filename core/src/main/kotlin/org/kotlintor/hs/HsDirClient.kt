package org.kotlintor.hs

import org.kotlintor.dir.Consensus
import org.kotlintor.dir.DirectoryAuthority
import org.kotlintor.dir.RouterStatus
import org.kotlintor.util.concat
import java.net.HttpURLConnection
import java.net.URI
import java.util.Base64
import java.util.TreeMap

/**
 * Locate responsible HSDirs and fetch encrypted v3 descriptors (rend-spec-v3).
 * Initial fetch uses clearnet DirPort HTTP (same bootstrap model as DirectoryClient);
 * later moves to BEGIN_DIR over Tor circuits.
 */
object HsDirRing {
    fun selectFetchDirs(
        consensus: Consensus,
        blindedPublic: ByteArray,
        period: HsTimePeriod,
        sharedRandom: ByteArray,
        nReplicas: Int = consensus.param("hsdir_n_replicas", 2).toInt(),
        spreadFetch: Int = consensus.param("hsdir_spread_fetch", 3).toInt(),
    ): List<RouterStatus> = selectDirs(
        consensus = consensus,
        blindedPublic = blindedPublic,
        period = period,
        sharedRandom = sharedRandom,
        nReplicas = nReplicas,
        spread = spreadFetch,
    )

    fun selectStoreDirs(
        consensus: Consensus,
        blindedPublic: ByteArray,
        period: HsTimePeriod,
        sharedRandom: ByteArray,
        nReplicas: Int = consensus.param("hsdir_n_replicas", 2).toInt(),
        spreadStore: Int = consensus.param("hsdir_spread_store", 4).toInt(),
    ): List<RouterStatus> = selectDirs(
        consensus = consensus,
        blindedPublic = blindedPublic,
        period = period,
        sharedRandom = sharedRandom,
        nReplicas = nReplicas,
        spread = spreadStore,
    )

    private fun selectDirs(
        consensus: Consensus,
        blindedPublic: ByteArray,
        period: HsTimePeriod,
        sharedRandom: ByteArray,
        nReplicas: Int,
        spread: Int,
    ): List<RouterStatus> {
        val hsdirs = consensus.relays.filter {
            it.isHsDir && it.isRunning && it.ed25519Identity != null
        }
        if (hsdirs.isEmpty()) return emptyList()

        val ring = TreeMap<ByteArrayKey, RouterStatus>()
        for (r in hsdirs) {
            val idx = HsKeyBlind.relayIndex(r.ed25519Identity!!, sharedRandom, period)
            ring[ByteArrayKey(idx)] = r
        }

        val chosen = LinkedHashSet<RouterStatus>()
        for (replica in 1..nReplicas) {
            val svcIdx = ByteArrayKey(HsKeyBlind.serviceIndex(blindedPublic, replica.toLong(), period))
            var taken = 0
            var walk = ring.ceilingEntry(svcIdx) ?: ring.firstEntry()
            val startKey = walk.key
            do {
                val node = walk.value
                if (node !in chosen) {
                    chosen += node
                    taken++
                    if (taken >= spread) break
                }
                walk = ring.higherEntry(walk.key) ?: ring.firstEntry()
            } while (walk.key != startKey && taken < spread)
        }
        return chosen.toList()
    }

    private class ByteArrayKey(val bytes: ByteArray) : Comparable<ByteArrayKey> {
        override fun compareTo(other: ByteArrayKey): Int {
            val n = minOf(bytes.size, other.bytes.size)
            for (i in 0 until n) {
                val a = bytes[i].toInt() and 0xff
                val b = other.bytes[i].toInt() and 0xff
                if (a != b) return a - b
            }
            return bytes.size - other.bytes.size
        }

        override fun equals(other: Any?): Boolean =
            other is ByteArrayKey && bytes.contentEquals(other.bytes)

        override fun hashCode(): Int = bytes.contentHashCode()
    }
}

class HsDescriptorClient {
    /**
     * Fetch encrypted HS descriptor body for [blindedPublic] from [dirs].
     * Returns raw descriptor text (still encrypted / signed outer layer).
     */
    fun fetchEncrypted(
        blindedPublic: ByteArray,
        dirs: List<RouterStatus>,
        fallbackAuthorities: List<DirectoryAuthority> = emptyList(),
    ): String {
        val id = Base64.getEncoder().withoutPadding().encodeToString(blindedPublic)
        var last: Exception? = null
        for (dir in dirs.shuffled()) {
            try {
                val url = "http://${dir.ip}:${dir.dirPort}/tor/hs/3/$id"
                return httpGet(url)
            } catch (e: Exception) {
                last = e
            }
        }
        for (auth in fallbackAuthorities.shuffled()) {
            try {
                val url = "http://${auth.address}:${auth.dirPort}/tor/hs/3/$id"
                return httpGet(url)
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException("HS descriptor fetch failed for blinded key", last)
    }

    private fun httpGet(url: String): String {
        val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            setRequestProperty("User-Agent", "kotlin-tor/0.1")
            instanceFollowRedirects = true
        }
        val code = conn.responseCode
        val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
            ?.readBytes() ?: ByteArray(0)
        if (code !in 200..299) {
            error("HTTP $code from $url")
        }
        return body.decodeToString()
    }
}

/** Client-side helpers for onion destinations. */
object HsClient {
    fun isOnionHost(host: String): Boolean = host.lowercase().endsWith(".onion")

    fun timePeriodForConsensus(consensus: Consensus): HsTimePeriod {
        val length = consensus.param("hsdir-interval", HsTimePeriod.DEFAULT_LENGTH_MINUTES)
        return HsTimePeriod.containing(consensus.validAfter, lengthMinutes = length)
    }

    /**
     * Client SRV selection (rend-spec FETCHUPLOADDESC).
     * Between a new SRV (00:00) and the next TP (12:00) use previous SRV;
     * between TP (12:00) and the next SRV (00:00) use current SRV.
     */
    fun sharedRandomForFetch(consensus: Consensus, period: HsTimePeriod): ByteArray {
        val hour = consensus.validAfter.atZone(java.time.ZoneOffset.UTC).hour
        val preferPrevious = hour < 12
        val primary = if (preferPrevious) consensus.sharedRandPrevious else consensus.sharedRandCurrent
        val secondary = if (preferPrevious) consensus.sharedRandCurrent else consensus.sharedRandPrevious
        return primary ?: secondary ?: DigestsDisaster.srv(period)
    }

    /** Both SRVs to try when the primary HSDir set returns 404. */
    fun sharedRandomCandidates(consensus: Consensus, period: HsTimePeriod): List<ByteArray> {
        val primary = sharedRandomForFetch(consensus, period)
        val out = mutableListOf(primary)
        val other = listOfNotNull(consensus.sharedRandCurrent, consensus.sharedRandPrevious)
            .firstOrNull { !it.contentEquals(primary) }
        if (other != null) out += other
        return out
    }

    /**
     * Service SRV for upload (rend-spec SERVICEUPLOAD / FETCHUPLOADDESC).
     * Between TP (12:00) and next SRV (00:00) prefer current; otherwise previous.
     */
    fun sharedRandomForUpload(consensus: Consensus, period: HsTimePeriod): ByteArray {
        val hour = consensus.validAfter.atZone(java.time.ZoneOffset.UTC).hour
        val preferCurrent = hour >= 12
        val primary = if (preferCurrent) consensus.sharedRandCurrent else consensus.sharedRandPrevious
        val secondary = if (preferCurrent) consensus.sharedRandPrevious else consensus.sharedRandCurrent
        return primary ?: secondary ?: DigestsDisaster.srv(period)
    }
}

/** Disaster SRV when consensus SRVs are missing (rend-spec). */
private object DigestsDisaster {
    fun srv(period: HsTimePeriod): ByteArray =
        org.kotlintor.crypto.Digests.sha3_256(
            concat(
                "shared-random-disaster".toByteArray(),
                org.kotlintor.util.u64be(period.lengthMinutes),
                org.kotlintor.util.u64be(period.intervalNum),
            ),
        )
}
