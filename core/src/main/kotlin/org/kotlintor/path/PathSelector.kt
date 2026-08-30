package org.kotlintor.path

import org.kotlintor.config.TorConfig
import org.kotlintor.dir.GeoIp
import org.kotlintor.dir.RouterStatus
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.writeTextCompat
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

data class CircuitPath(
    val guard: RouterStatus,
    val middle: RouterStatus,
    val exit: RouterStatus,
)

/**
 * Persistent primary guard sample entry (guard-spec).
 *
 * @param firstListedMs wall-clock when first sampled
 * @param confirmed true after the guard successfully built a circuit
 * @param confirmedAtMs when confirmed (or 0)
 * @param unlistedSinceMs when dropped from consensus (or 0 while listed)
 */
data class GuardEntry(
    val fingerprintHex: String,
    val firstListedMs: Long,
    val confirmed: Boolean = false,
    val confirmedAtMs: Long = 0L,
    val unlistedSinceMs: Long = 0L,
)

/**
 * Guard-aware path selection (guard-spec + path-spec + client-local diversity).
 *
 * Maintains a **sampled primary set** of up to [TorConfig.numEntryGuards] entry guards with
 * lifetimes / confirmed flags, persisted under [stateFile].
 * Enforces descriptor family separation when [noteFamily] has been called.
 *
 * Country / continent / recent-hop filters are **client-local** only: they do not change
 * consensus documents or CREATE/EXTEND wire formats.
 */
class PathSelector(
    private val config: TorConfig,
    private val stateFile: Path,
) {
    private val sampled: MutableList<GuardEntry> = loadSample().toMutableList()
    /** Fingerprint → family member fingerprints (including self). */
    private val families = mutableMapOf<String, Set<String>>()
    private val vanguards = VanguardsLite(config)
    val entryGuardFsm: EntryGuardFsm = EntryGuardFsm()
    private val recentHops = RecentHopAvoider(
        capacity = config.circuitRecentHopHistorySize.coerceIn(1, 10_000),
    )

    /** Optional GeoIP DB for country/continent diversity (set by [TorClient]). */
    @Volatile
    var geoIp: GeoIp.Database? = null

    fun noteFamily(fingerprintHex: String, members: Set<String>) {
        val fp = fingerprintHex.uppercase()
        val all = (members.map { it.uppercase() } + fp).toSet()
        families[fp] = all
        for (m in all) {
            families[m] = (families[m] ?: emptySet()) + all
        }
        org.kotlintor.dir.NodeFamily.parse(
            members.joinToString(" "),
            selfFp = fp,
        )
    }

    /** Clear middle/exit reuse history (e.g. NEWNYM). Does not rotate sticky guards. */
    fun clearRecentHops() {
        recentHops.clear()
    }

    fun select(
        relays: List<RouterStatus>,
        exitHostname: String? = null,
        extraExclude: Set<String> = emptySet(),
        rotateGuard: Boolean = false,
        /** When set and in LongLivedPorts, prefer Stable exits (path-spec). */
        exitPort: Int? = null,
    ): CircuitPath {
        if (rotateGuard) rotateGuard()
        recentHops.resize(config.circuitRecentHopHistorySize.coerceIn(1, 10_000))
        val exclude = (
            config.excludeNodes + config.excludeExitNodes + extraExclude + config.nodeFamiliesFlattened()
            ).map { it.uppercase() }.toSet()
        fun allowed(r: RouterStatus): Boolean {
            val fp = r.fingerprintHex
            if (!(r.isRunning && r.isFast && fp !in exclude && r.nickname.uppercase() !in exclude)) {
                return false
            }
            if (config.runtime.geoIpExcludeUnknown && countryOf(r) == null && geoIp != null) {
                return false
            }
            val policy = config.orReachablePolicy()
            return policy.allows(r.ip, r.orPort)
        }

        val guards = relays.filter { it.isGuard && allowed(it) }.let { pool ->
            val allow = config.entryNodes.map { it.uppercase() }.toSet()
            if (allow.isEmpty()) {
                pool
            } else {
                val filtered = pool.filter {
                    it.fingerprintHex in allow || it.nickname.uppercase() in allow
                }
                when {
                    filtered.isNotEmpty() -> filtered
                    config.strictNodes -> error("StrictNodes: no EntryNodes match in consensus")
                    else -> pool
                }
            }
        }
        val preferStable = exitPort != null && config.isLongLivedPort(exitPort)
        fun inAllowlist(r: RouterStatus, allow: List<String>): Boolean {
            if (allow.isEmpty()) return true
            val want = allow.map { it.uppercase().removePrefix("$") }.toSet()
            return r.fingerprintHex.uppercase() in want || r.nickname.uppercase() in want
        }
        val middles = relays.filter {
            allowed(it) && !it.isExit && inAllowlist(it, config.middleNodes)
        }.let { pool ->
            if (preferStable) pool.filter { it.isStable }.ifEmpty { pool } else pool
        }
        val exits = relays.filter {
            it.isExit && allowed(it) &&
                it.fingerprintHex !in config.excludeExitNodes.map { e -> e.uppercase() } &&
                inAllowlist(it, config.exitNodes)
        }.let { pool ->
            if (preferStable) pool.filter { it.isStable }.ifEmpty { pool } else pool
        }

        require(guards.isNotEmpty()) { "no usable guards in consensus" }
        require(middles.isNotEmpty()) { "no usable middles" }
        require(exits.isNotEmpty()) { "no usable exits" }

        val bridgeGuard = bridgeAsGuard()
        val guard = bridgeGuard ?: if (config.useEntryGuards) {
            pickGuard(guards)
        } else {
            weightedPick(guards)
        }
        val prior = mutableListOf(guard)

        val middle = pickDiverseHop(middles, prior, role = "middle")
        prior += middle
        val exit = pickDiverseHop(exits, prior, role = "exit")

        if (config.circuitAvoidRecentHops) {
            recentHops.recordMiddleAndExit(middle.fingerprintHex, exit.fingerprintHex)
        }

        @Suppress("UNUSED_EXPRESSION")
        exitHostname
        return CircuitPath(guard, middle, exit)
    }

    /** Build a path that ends at a specific relay (e.g. HSDir for BEGIN_DIR). */
    fun selectEndingAt(
        relays: List<RouterStatus>,
        lastHop: RouterStatus,
        extraExclude: Set<String> = emptySet(),
    ): CircuitPath {
        if (config.vanguardsLiteEnabled) {
            vanguards.ensureSampled(relays)
            return vanguards.selectHsPath(relays, lastHop) { guards -> pickGuard(guards) }
        }
        val exclude = (config.excludeNodes + extraExclude).map { it.uppercase() }.toSet()
        fun allowed(r: RouterStatus): Boolean {
            val fp = r.fingerprintHex
            return r.isRunning && r.isFast && fp !in exclude &&
                fp != lastHop.fingerprintHex
        }
        val guards = relays.filter { it.isGuard && allowed(it) }
        val middles = relays.filter { allowed(it) && !it.isExit }
        require(guards.isNotEmpty()) { "no usable guards" }
        require(middles.isNotEmpty()) { "no usable middles" }

        val guard = pickGuard(guards)
        val prior = mutableListOf(guard, lastHop)
        val middle = pickDiverseHop(middles, prior, role = "middle")
        if (config.circuitAvoidRecentHops) {
            recentHops.record(middle.fingerprintHex)
        }
        return CircuitPath(guard, middle, lastHop)
    }

    fun vanguardL2(): List<String> = vanguards.l2Fingerprints()
    fun vanguardL3(): List<String> = vanguards.l3Fingerprints()

    /** Mark a sampled guard as confirmed after a successful circuit. */
    fun confirmGuard(fingerprintHex: String) {
        val fp = fingerprintHex.uppercase()
        val i = sampled.indexOfFirst { it.fingerprintHex == fp }
        if (i < 0) return
        val now = System.currentTimeMillis()
        sampled[i] = sampled[i].copy(confirmed = true, confirmedAtMs = now)
        entryGuardFsm.noteSuccess(fp)
        saveSample()
    }

    /** Drop the entire sampled set (e.g. after persistent circuit failures). */
    fun rotateGuard() {
        sampled.clear()
        Files.deleteIfExists(stateFile)
    }

    fun noteGuardFailure(fingerprintHex: String) {
        entryGuardFsm.noteFailure(fingerprintHex)
    }

    /** Fingerprints currently in the primary sample (for tests / GETINFO). */
    fun sampledGuards(): List<String> = sampled.map { it.fingerprintHex }

    fun sampledEntries(): List<GuardEntry> = sampled.toList()

    /** Test/debug: fingerprints currently avoided as recent middle/exit. */
    fun recentHopFingerprints(): Set<String> = recentHops.fingerprints()

    private fun familyOf(fp: String): Set<String> = families[fp.uppercase()] ?: setOf(fp.uppercase())

    private fun sharesFamily(fp: String, used: Set<String>): Boolean {
        val fam = familyOf(fp)
        return fam.any { it in used }
    }

    private fun countryOf(r: RouterStatus): String? = geoIp?.country(r.ip)?.lowercase()

    private fun continentOf(r: RouterStatus): GeoRegion.Continent =
        GeoRegion.continentOf(countryOf(r))

    /**
     * Pick a hop with fail-soft diversity: full filters → drop recent → continent → country → base.
     */
    private fun pickDiverseHop(
        pool: List<RouterStatus>,
        priorHops: List<RouterStatus>,
        role: String,
    ): RouterStatus {
        val usedFp = mutableSetOf<String>()
        for (h in priorHops) {
            usedFp += h.fingerprintHex.uppercase()
            usedFp += familyOf(h.fingerprintHex)
        }
        val priorCountries = priorHops.mapNotNull { countryOf(it) }.toSet()
        val priorContinents = priorHops
            .map { continentOf(it) }
            .filter { it != GeoRegion.Continent.UNKNOWN }
            .toSet()

        fun baseOk(r: RouterStatus): Boolean {
            val fp = r.fingerprintHex.uppercase()
            if (fp in usedFp || sharesFamily(fp, usedFp)) return false
            if (config.enforceDistinctSubnets) {
                for (h in priorHops) {
                    if (sameSlash16(r.ip, h.ip)) return false
                }
            }
            return true
        }

        fun countryOk(r: RouterStatus): Boolean {
            if (!config.enforceDistinctCountries) return true
            val cc = countryOf(r) ?: return true
            return cc !in priorCountries
        }

        fun continentOk(r: RouterStatus): Boolean {
            if (!config.enforceDistinctContinents) return true
            val cont = continentOf(r)
            if (cont == GeoRegion.Continent.UNKNOWN) return true
            return cont !in priorContinents
        }

        fun recentOk(r: RouterStatus): Boolean {
            if (!config.circuitAvoidRecentHops) return true
            return !recentHops.contains(r.fingerprintHex)
        }

        val levels = listOf(
            { r: RouterStatus -> baseOk(r) && countryOk(r) && continentOk(r) && recentOk(r) },
            { r: RouterStatus -> baseOk(r) && countryOk(r) && continentOk(r) },
            { r: RouterStatus -> baseOk(r) && countryOk(r) },
            { r: RouterStatus -> baseOk(r) },
            { r: RouterStatus -> r.fingerprintHex.uppercase() !in usedFp },
        )
        for ((idx, pred) in levels.withIndex()) {
            val filtered = pool.filter(pred)
            if (filtered.isNotEmpty()) {
                if (idx > 0) {
                    System.err.println(
                        "path: relaxed diversity for $role to level=$idx (pool was empty)",
                    )
                }
                return weightedPick(diversityCandidatePool(filtered))
            }
        }
        return weightedPick(diversityCandidatePool(pool))
    }

    /**
     * When the pool is large, take a SecureRandom subsample of the top bandwidth
     * relays so the heaviest exit is not almost-deterministic.
     */
    private fun diversityCandidatePool(relays: List<RouterStatus>): List<RouterStatus> {
        if (relays.size <= DIVERSITY_TOP_K) return relays
        val top = relays.sortedByDescending { it.bandwidth.coerceAtLeast(1) }
            .take(DIVERSITY_TOP_K * 2)
            .toMutableList()
        // Fisher–Yates shuffle then keep K.
        for (i in top.lastIndex downTo 1) {
            val j = SecureRandomSource.nextInt(i + 1)
            val tmp = top[i]
            top[i] = top[j]
            top[j] = tmp
        }
        return top.take(DIVERSITY_TOP_K)
    }

    private fun pickGuard(guards: List<RouterStatus>): RouterStatus {
        val now = System.currentTimeMillis()
        val listed = guards.map { it.fingerprintHex }.toSet()
        for (i in sampled.indices) {
            val e = sampled[i]
            if (e.fingerprintHex !in listed) {
                if (e.unlistedSinceMs == 0L) {
                    sampled[i] = e.copy(unlistedSinceMs = now)
                } else if (now - e.unlistedSinceMs > REMOVE_UNLISTED_AFTER_MS) {
                    sampled[i] = e.copy(fingerprintHex = "") // mark for removal
                }
            } else if (e.unlistedSinceMs != 0L) {
                sampled[i] = e.copy(unlistedSinceMs = 0L)
            }
        }
        sampled.removeAll { it.fingerprintHex.isEmpty() }
        val lifetimeMs = TimeUnit.DAYS.toMillis(config.guardLifetimeDays.coerceAtLeast(1))
        sampled.removeAll { now - it.firstListedMs > lifetimeMs }

        val sampleSize = config.numEntryGuards.coerceIn(1, 16)
        while (sampled.size < sampleSize) {
            val candidates = guards.filter { g -> sampled.none { it.fingerprintHex == g.fingerprintHex } }
            if (candidates.isEmpty()) break
            val pick = weightedPick(candidates)
            sampled += GuardEntry(
                fingerprintHex = pick.fingerprintHex,
                firstListedMs = now,
            )
        }
        saveSample()
        require(sampled.isNotEmpty()) { "empty guard sample" }

        val usable = sampled.filter {
            it.fingerprintHex in listed && !entryGuardFsm.getOrCreate(it.fingerprintHex).pathBiasDisabled
        }
        require(usable.isNotEmpty()) { "no listed sampled guards" }
        val fsmPick = entryGuardFsm.pickPreferred(usable.map { it.fingerprintHex })
        val fp = fsmPick
            ?: usable.filter { it.confirmed }.ifEmpty { usable }
                .let { it[SecureRandomSource.nextInt(it.size)].fingerprintHex }
        entryGuardFsm.noteAttempt(fp)
        return guards.first { it.fingerprintHex.equals(fp, ignoreCase = true) }
    }

    private fun weightedPick(relays: List<RouterStatus>): RouterStatus {
        require(relays.isNotEmpty()) { "empty relay list for weighted pick" }
        val total = relays.sumOf { it.bandwidth.coerceAtLeast(1) }.coerceAtLeast(1L)
        var r = SecureRandomSource.nextLong(total)
        for (relay in relays) {
            r -= relay.bandwidth.coerceAtLeast(1)
            if (r < 0) return relay
        }
        return relays.last()
    }

    private fun loadSample(): List<GuardEntry> {
        if (!Files.exists(stateFile)) return emptyList()
        val sampleSize = config.numEntryGuards.coerceIn(1, 16)
        return Files.readAllLines(stateFile).mapNotNull { line ->
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) return@mapNotNull null
            val parts = t.split(Regex("\\s+"))
            val fp = parts[0].uppercase()
            if (fp.length != 40) return@mapNotNull null
            if (parts.size == 1) {
                return@mapNotNull GuardEntry(fp, System.currentTimeMillis())
            }
            GuardEntry(
                fingerprintHex = fp,
                firstListedMs = parts.getOrNull(1)?.toLongOrNull() ?: System.currentTimeMillis(),
                confirmed = parts.getOrNull(2) == "1",
                confirmedAtMs = parts.getOrNull(3)?.toLongOrNull() ?: 0L,
                unlistedSinceMs = parts.getOrNull(4)?.toLongOrNull() ?: 0L,
            )
        }.distinctBy { it.fingerprintHex }.take(sampleSize)
    }

    private fun saveSample() {
        Files.createDirectories(stateFile.parent)
        val body = sampled.joinToString("\n") { e ->
            "${e.fingerprintHex} ${e.firstListedMs} ${if (e.confirmed) 1 else 0} ${e.confirmedAtMs} ${e.unlistedSinceMs}"
        } + if (sampled.isNotEmpty()) "\n" else ""
        stateFile.writeTextCompat(body)
    }

    /** When UseBridges, force first hop to the configured Bridge line. */
    private fun bridgeAsGuard(): RouterStatus? {
        if (!config.useBridges || config.bridges.isEmpty()) return null
        val line = org.kotlintor.pt.BridgeLine.parse(config.bridges.first()) ?: return null
        val fpHex = line.fingerprintHex?.uppercase()?.filter { it in '0'..'9' || it in 'A'..'F' }
        val identity = if (fpHex != null && fpHex.length >= 40) {
            org.kotlintor.util.hexToBytes(fpHex.take(40))
        } else {
            ByteArray(20)
        }
        return RouterStatus(
            nickname = "Bridge",
            identity = identity,
            digest = ByteArray(20),
            publication = java.time.Instant.EPOCH,
            ip = line.host,
            orPort = line.port,
            dirPort = 0,
            flags = setOf("Running", "Fast", "Guard", "Stable", "V2Dir"),
            version = null,
            proto = emptyMap(),
            bandwidth = 1_000_000,
        )
    }

    companion object {
        /** Primary sample size (guard-spec uses ~3 confirmed primaries). */
        const val SAMPLE_SIZE = 3
        /** Top-K subsample size for entropy-preserving weighted pick. */
        const val DIVERSITY_TOP_K = 32
        /** ~8 months primary guard lifetime (guard-spec order of magnitude). */
        val GUARD_LIFETIME_MS: Long = TimeUnit.DAYS.toMillis(240)
        /** Remove from sample after ~20 days unlisted. */
        val REMOVE_UNLISTED_AFTER_MS: Long = TimeUnit.DAYS.toMillis(20)
    }
}

private fun TorConfig.nodeFamiliesFlattened(): List<String> = nodeFamily

private fun sameSlash16(a: String, b: String): Boolean {
    val pa = a.split('.')
    val pb = b.split('.')
    if (pa.size != 4 || pb.size != 4) return false
    return pa[0] == pb[0] && pa[1] == pb[1]
}
