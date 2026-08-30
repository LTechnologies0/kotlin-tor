package org.kotlintor.dir

import org.kotlintor.util.toHex

/**
 * Directory authority voting schedule + act loop (C Tor `voting_schedule.h` /
 * `dirvote_act` in `dirvote.c`).
 *
 * Signing: [DirVoteActor.publishSigned] (Ed25519 testing) and
 * [DirVoteActor.publishSignedRsa] (authority cert signing key / sha1 PKCS1).
 */
object DirVote {
    const val MIN_VOTE_SECONDS: Int = 2
    const val MIN_DIST_SECONDS: Int = 2
    const val MIN_VOTE_INTERVAL: Int = 300
    const val MIN_VOTE_INTERVAL_TESTING: Int = (MIN_VOTE_SECONDS + MIN_DIST_SECONDS + 1) * 2
    const val MIN_SUPPORTED_CONSENSUS_METHOD: Int = 32
    const val MAX_SUPPORTED_CONSENSUS_METHOD: Int = 35
    const val DEFAULT_MAX_UNMEASURED_BW_KB: Int = 20

    const val DGV_BY_ID: Int = 1
    const val DGV_INCLUDE_PENDING: Int = 2
    const val DGV_INCLUDE_PREVIOUS: Int = 4

    /** C Tor `DIRVOTE_UNIVERSAL_FLAGS` subset used in votes. */
    val UNIVERSAL_FLAGS: List<String> =
        listOf("Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "NoEdConsensus", "Stable", "StaleDesc", "Running", "Valid", "V2Dir")

    data class Timing(
        val voteIntervalSec: Int,
        val voteSeconds: Int,
        val distSeconds: Int,
        val testing: Boolean = false,
    ) {
        init {
            val minInterval = if (testing) MIN_VOTE_INTERVAL_TESTING else MIN_VOTE_INTERVAL
            require(voteIntervalSec >= minInterval) {
                "voteInterval $voteIntervalSec < min $minInterval"
            }
            require(voteSeconds >= MIN_VOTE_SECONDS)
            require(distSeconds >= MIN_DIST_SECONDS)
            require(voteSeconds + distSeconds < voteIntervalSec) {
                "voteSeconds+distSeconds must fit in voteInterval"
            }
        }
    }

    data class Schedule(
        val votingStarts: Long,
        val fetchMissingVotes: Long,
        val votingEnds: Long,
        val fetchMissingSignatures: Long,
        val intervalStarts: Long,
        val interval: Int,
        var haveVoted: Boolean = false,
        var haveFetchedMissingVotes: Boolean = false,
        var haveBuiltConsensus: Boolean = false,
        var haveFetchedMissingSignatures: Boolean = false,
        var havePublishedConsensus: Boolean = false,
        var createdOnDemand: Boolean = false,
        var liveConsensusValidAfter: Long = 0,
    )

    enum class Phase {
        VOTE,
        FETCH_VOTES,
        COMPUTE_CONSENSUS,
        FETCH_SIGNATURES,
        PUBLISH,
        IDLE,
    }

    /**
     * Build schedule for interval starting at [intervalStarts] (valid-after).
     * Layout matches C Tor: vote at valid-after − voteSeconds − distSeconds, etc.
     */
    fun buildSchedule(timing: Timing, intervalStartsEpochSec: Long): Schedule {
        val voteAt = intervalStartsEpochSec - timing.distSeconds - timing.voteSeconds
        val fetchVotesAt = intervalStartsEpochSec - timing.distSeconds
        val votingEnds = fetchVotesAt // compute consensus when dist window opens
        val fetchSigsAt = intervalStartsEpochSec - (timing.distSeconds / 2).coerceAtLeast(1)
        return Schedule(
            votingStarts = voteAt,
            fetchMissingVotes = fetchVotesAt,
            votingEnds = votingEnds,
            fetchMissingSignatures = fetchSigsAt,
            intervalStarts = intervalStartsEpochSec,
            interval = timing.voteIntervalSec,
        )
    }

    /** Next valid-after after [now], aligned to [timing.voteIntervalSec] from epoch. */
    fun nextValidAfter(timing: Timing, nowEpochSec: Long): Long {
        val i = timing.voteIntervalSec.toLong()
        val aligned = ((nowEpochSec / i) + 1) * i
        return aligned
    }

    fun preferredConsensusMethod(votes: List<Int>): Int {
        val supported = votes.filter { it in MIN_SUPPORTED_CONSENSUS_METHOD..MAX_SUPPORTED_CONSENSUS_METHOD }
        if (supported.isEmpty()) return MIN_SUPPORTED_CONSENSUS_METHOD
        val counts = supported.groupingBy { it }.eachCount()
        val majority = (votes.size + 1) / 2
        return counts.filter { it.value >= majority }.keys.maxOrNull()
            ?: supported.maxOrNull()!!
    }

    /**
     * C Tor `authority_cert_dup` — clone certificate PEM/document text.
     */
    fun authorityCertDup(certDocument: String): String = certDocument

    data class RouterInfoLite(
        val identityHex: String,
        val ipv4: String = "0.0.0.0",
        val ipv6: String? = null,
        val orPort: Int = 0,
        val bandwidthKb: Int = 0,
        val publishedEpochSec: Long = 0,
        val isRunning: Boolean = true,
    )

    /** C Tor `compare_routerinfo_by_ipv4` — negative if a < b. */
    fun compareRouterinfoByIpv4(a: RouterInfoLite, b: RouterInfoLite): Int =
        compareIp4(a.ipv4, b.ipv4).takeIf { it != 0 }
            ?: a.orPort.compareTo(b.orPort).takeIf { it != 0 }
            ?: a.identityHex.compareTo(b.identityHex, ignoreCase = true)

    /** C Tor `compare_routerinfo_by_ipv6`. */
    fun compareRouterinfoByIpv6(a: RouterInfoLite, b: RouterInfoLite): Int {
        val aa = a.ipv6 ?: ""
        val bb = b.ipv6 ?: ""
        return aa.compareTo(bb).takeIf { it != 0 }
            ?: a.orPort.compareTo(b.orPort).takeIf { it != 0 }
            ?: a.identityHex.compareTo(b.identityHex, ignoreCase = true)
    }

    /**
     * C Tor `compare_routerinfo_usefulness` — prefer higher bandwidth / newer published.
     * Returns negative if [first] is less useful than [second].
     */
    fun compareRouterinfoUsefulness(first: RouterInfoLite, second: RouterInfoLite): Int {
        if (first.isRunning != second.isRunning) return if (first.isRunning) 1 else -1
        if (first.bandwidthKb != second.bandwidthKb) return first.bandwidthKb.compareTo(second.bandwidthKb)
        return first.publishedEpochSec.compareTo(second.publishedEpochSec)
    }

    /** C Tor `compute_consensus_package_lines` — join validated RecommendedPackages. */
    fun computeConsensusPackageLines(packageLines: List<String>): String =
        packageLines.filter { RecommendPkg.validate(it) }.joinToString("\n") { "package $it" }

    private fun compareIp4(a: String, b: String): Int {
        fun octets(s: String): Long {
            val p = s.split('.')
            if (p.size != 4) return 0L
            var v = 0L
            for (o in p) v = (v shl 8) or (o.toLongOrNull()?.coerceIn(0, 255) ?: 0)
            return v
        }
        return octets(a).compareTo(octets(b))
    }

    /**
     * C Tor `dirserv_generate_networkstatus_vote_obj` — build a minimal vote document body.
     */
    fun dirservGenerateNetworkstatusVoteObj(
        routers: List<RouterInfoLite>,
        published: String = "2020-01-01 00:00:00",
        fingerprint: String = "00".repeat(20),
    ): String = buildString {
        appendLine("network-status-version 3")
        appendLine("vote-status vote")
        appendLine("published $published")
        appendLine("fingerprint $fingerprint")
        appendLine("known-flags ${UNIVERSAL_FLAGS.joinToString(" ")}")
        for (r in routers) {
            appendLine(
                "r Unnamed ${r.identityHex} AA $published ${r.ipv4} ${r.orPort} 0",
            )
            appendLine(BandwidthVote.formatWLine(r.bandwidthKb.toLong()))
            val flags = buildList {
                if (r.isRunning) add("Running")
                add("Valid")
                add("V2Dir")
            }
            appendLine("s ${flags.joinToString(" ")}")
        }
        appendLine("directory-footer")
    }

    /** C Tor `dirvote_act` — advance [actor] schedule; returns next wake epoch. */
    fun dirvoteAct(actor: DirVoteActor, nowEpochSec: Long): Long = actor.act(nowEpochSec)

    /** C Tor `dirvote_add_vote`. */
    fun dirvoteAddVote(actor: DirVoteActor, body: String, from: String = "local"): BandwidthVote.VoteDocument =
        actor.addVote(body, from)

    /** C Tor `dirvote_add_signatures` — attach signature block lines to consensus body. */
    fun dirvoteAddSignatures(consensusBody: String, signatureBlock: String): String {
        val body = consensusBody.trimEnd()
        val sig = signatureBlock.trim()
        return if (body.contains("directory-signature")) {
            body + "\n" + sig + "\n"
        } else {
            body.trimEnd('\n') + "\n" + sig + "\n"
        }
    }

    private val pendingCommits = LinkedHashMap<String, String>()

    /** C Tor `dirvote_clear_commits`. */
    fun dirvoteClearCommits() {
        pendingCommits.clear()
    }

    fun dirvotePendingCommitCount(): Int = pendingCommits.size

    fun dirvoteNoteCommit(identityHex: String, commitLine: String) {
        pendingCommits[identityHex.lowercase()] = commitLine
    }

    /**
     * C Tor `dirvote_compute_params` — majority param map from vote param lines.
     */
    fun dirvoteComputeParams(voteParamMaps: List<Map<String, Int>>): Map<String, Int> {
        if (voteParamMaps.isEmpty()) return emptyMap()
        val keys = voteParamMaps.flatMap { it.keys }.toSet()
        val out = LinkedHashMap<String, Int>()
        val majority = (voteParamMaps.size + 1) / 2
        for (k in keys.sorted()) {
            val vals = voteParamMaps.mapNotNull { it[k] }.sorted()
            if (vals.size < majority) continue
            out[k] = vals[vals.size / 2]
        }
        return out
    }

    /**
     * C Tor `dirvote_create_microdescriptor` — minimal onion-key microdesc body.
     */
    fun dirvoteCreateMicrodescriptor(onionKeyPem: String, family: String? = null): String =
        buildString {
            appendLine("onion-key")
            append(onionKeyPem.trimEnd())
            appendLine()
            if (!family.isNullOrBlank()) appendLine("family $family")
        }

    /** C Tor `dirvote_get_vote`. */
    fun dirvoteGetVote(actor: DirVoteActor, key: String): BandwidthVote.VoteDocument? =
        actor.pendingVotes().entries.firstOrNull { it.key.contains(key) }?.value
            ?: actor.pendingVotes().values.firstOrNull()

    /**
     * C Tor `dirvote_dirreq_get_status_vote` — return cached vote body or empty.
     */
    fun dirvoteDirreqGetStatusVote(actor: DirVoteActor): String {
        val v = actor.pendingVotes().values.firstOrNull() ?: return ""
        return v.raw.ifBlank {
            dirservGenerateNetworkstatusVoteObj(
                v.routers.mapNotNull { r ->
                    val id = r.identityHex ?: return@mapNotNull null
                    RouterInfoLite(id, bandwidthKb = (r.measured ?: r.bandwidth).toInt())
                },
            )
        }
    }

    /** C Tor `dirvote_format_all_microdesc_vote_lines`. */
    fun dirvoteFormatAllMicrodescVoteLines(microdescs: List<String>): String =
        microdescs.joinToString("\n") { md ->
            val dig = org.kotlintor.crypto.Digests.sha256(md.toByteArray(Charsets.UTF_8))
            "m " + dig.toHex().lowercase()
        }

    /** C Tor `dirvote_free_all` — clear actor votes + commits. */
    fun dirvoteFreeAll(actor: DirVoteActor? = null) {
        dirvoteClearCommits()
        actor?.clearVotes()
    }

    /** C Tor `dirvote_get_intermediate_param_value`. */
    fun dirvoteGetIntermediateParamValue(
        paramMaps: List<Map<String, Int>>,
        key: String,
        default: Int = 0,
    ): Int = dirvoteComputeParams(paramMaps)[key] ?: default

    /** C Tor `dirvote_parse_sr_commits` — parse shared-rand-commit lines from vote text. */
    fun dirvoteParseSrCommits(voteText: String): List<SharedRandom.Commit> {
        val out = ArrayList<SharedRandom.Commit>()
        for (raw in voteText.lineSequence()) {
            val line = raw.trim()
            if (!line.startsWith(SharedRandom.COMMIT_NS)) continue
            val p = line.split(Regex("\\s+"))
            if (p.size < 5) continue
            val fp = p[3]
            val encCommit = p[4]
            val encReveal = p.getOrNull(5)
            if (fp.length != 40 || encCommit.length != SharedRandom.COMMIT_BASE64_LEN) continue
            if (encReveal != null && encReveal.length == SharedRandom.REVEAL_BASE64_LEN) {
                if (SharedRandom.commitDecode(encCommit, encReveal)) {
                    val id = org.kotlintor.util.hexToBytes(fp)
                    if (id.size == 20) {
                        val revealRaw = runCatching {
                            java.util.Base64.getDecoder().decode(encReveal)
                        }.getOrNull() ?: continue
                        if (revealRaw.size >= 8 + SharedRandom.RANDOM_NUMBER_LEN) {
                            out += SharedRandom.Commit(
                                rsaIdentity = id,
                                commitTs = 0,
                                revealTs = 0,
                                randomNumber = revealRaw.copyOfRange(8, 8 + SharedRandom.RANDOM_NUMBER_LEN),
                                hashedReveal = org.kotlintor.crypto.Digests.sha3_256(
                                    encReveal.toByteArray(Charsets.US_ASCII),
                                ),
                                encodedReveal = encReveal,
                                encodedCommit = encCommit,
                            )
                        }
                    }
                }
            }
        }
        return out
    }

    /** C Tor `format_networkstatus_vote` — alias of vote object generation. */
    fun formatNetworkstatusVote(
        routers: List<RouterInfoLite>,
        published: String = "2020-01-01 00:00:00",
        fingerprint: String = "00".repeat(20),
    ): String = dirservGenerateNetworkstatusVoteObj(routers, published, fingerprint)

    /** C Tor `format_recommended_version_list`. */
    fun formatRecommendedVersionList(versions: List<String>): String =
        versions.joinToString(",") { it.trim() }.let { "recommended-client-versions $it" }

    /**
     * C Tor `get_all_possible_sybil` / `get_sybil_list_by_ip_version` —
     * identities sharing the same IP beyond [maxPerAddr].
     */
    fun getAllPossibleSybil(
        routers: List<RouterInfoLite>,
        maxPerAddr: Int = 2,
    ): Set<String> {
        val byIp = routers.groupBy { it.ipv4 }
        val out = LinkedHashSet<String>()
        for ((_, group) in byIp) {
            if (group.size > maxPerAddr) {
                group.drop(maxPerAddr).forEach { out += it.identityHex.lowercase() }
            }
        }
        return out
    }

    fun getSybilListByIpVersion(
        routers: List<RouterInfoLite>,
        ipv6: Boolean = false,
        maxPerAddr: Int = 2,
    ): Set<String> {
        if (!ipv6) return getAllPossibleSybil(routers, maxPerAddr)
        val byIp = routers.groupBy { it.ipv6 ?: "" }.filterKeys { it.isNotEmpty() }
        val out = LinkedHashSet<String>()
        for ((_, group) in byIp) {
            if (group.size > maxPerAddr) {
                group.drop(maxPerAddr).forEach { out += it.identityHex.lowercase() }
            }
        }
        return out
    }

    /** C Tor `make_consensus_method_list`. */
    fun makeConsensusMethodList(
        min: Int = MIN_SUPPORTED_CONSENSUS_METHOD,
        max: Int = MAX_SUPPORTED_CONSENSUS_METHOD,
    ): String = (min..max).joinToString(" ")

    /**
     * C Tor `networkstatus_compute_bw_weights_v10` — simplified equal weights line.
     */
    fun networkstatusComputeBwWeightsV10(
        weightScale: Int = 10_000,
    ): String =
        "bandwidth-weights Wbd=$weightScale Wbe=$weightScale Wbg=$weightScale Wbm=$weightScale " +
            "Wdb=$weightScale Web=$weightScale Wed=$weightScale Wee=$weightScale Weg=$weightScale " +
            "Wem=$weightScale Wgb=$weightScale Wgd=$weightScale Wgg=$weightScale Wgm=$weightScale " +
            "Wmb=$weightScale Wmd=$weightScale Wme=$weightScale Wmg=$weightScale Wmm=$weightScale"

    /** C Tor `networkstatus_add_detached_signatures`. */
    fun networkstatusAddDetachedSignatures(
        consensusBody: String,
        detached: DetachedSignatures.Detached,
    ): String = DetachedSignatures.attachToConsensus(consensusBody, detached.signatures)
}

/**
 * Mutable dirvote actor — mirrors `dirvote_act` phase transitions.
 */
class DirVoteActor(
    private var timing: DirVote.Timing,
    private var schedule: DirVote.Schedule,
    private val onVote: () -> Unit = {},
    private val onFetchVotes: () -> Unit = {},
    private val onComputeConsensus: () -> Unit = {},
    private val onFetchSignatures: () -> Unit = {},
    private val onPublish: () -> Unit = {},
    val keypin: Keypin.Journal = Keypin.Journal(),
    val consCache: ConsCache = ConsCache(),
    val reachability: ReachabilityTracker = ReachabilityTracker(),
    val guardFractions: MutableMap<String, Int> = LinkedHashMap(),
    val processDescs: ProcessDescs = ProcessDescs(),
    val authMode: AuthModeOptions = AuthModeOptions(authoring = true),
    val consDiffMgr: ConsDiffMgr = ConsDiffMgr(),
) {
    fun recalculate(nowEpochSec: Long) {
        val next = DirVote.nextValidAfter(timing, nowEpochSec)
        schedule = DirVote.buildSchedule(timing, next).copy(createdOnDemand = false)
    }

    /**
     * Advance schedule; returns epoch seconds of next wake (or [Long.MAX_VALUE] if idle).
     */
    fun act(nowEpochSec: Long): Long {
        if (schedule.createdOnDemand) recalculate(nowEpochSec)

        fun step(whenField: Long, done: Boolean, mark: () -> Unit, action: () -> Unit): Long? {
            if (done) return null
            if (whenField > nowEpochSec) return whenField
            action()
            mark()
            return null
        }

        step(schedule.votingStarts, schedule.haveVoted, { schedule.haveVoted = true }, onVote)
            ?.let { return it }
        step(schedule.fetchMissingVotes, schedule.haveFetchedMissingVotes, {
            schedule.haveFetchedMissingVotes = true
        }, onFetchVotes)?.let { return it }
        step(schedule.votingEnds, schedule.haveBuiltConsensus, {
            schedule.haveBuiltConsensus = true
        }, onComputeConsensus)?.let { return it }
        step(schedule.fetchMissingSignatures, schedule.haveFetchedMissingSignatures, {
            schedule.haveFetchedMissingSignatures = true
        }, onFetchSignatures)?.let { return it }
        step(schedule.intervalStarts, schedule.havePublishedConsensus, {
            schedule.havePublishedConsensus = true
        }, onPublish)?.let { return it }

        // Roll to next interval.
        val nextStart = schedule.intervalStarts + schedule.interval
        schedule = DirVote.buildSchedule(timing, nextStart)
        return schedule.votingStarts
    }

    fun currentPhase(nowEpochSec: Long): DirVote.Phase = when {
        !schedule.haveVoted && nowEpochSec >= schedule.votingStarts -> DirVote.Phase.VOTE
        !schedule.haveFetchedMissingVotes && nowEpochSec >= schedule.fetchMissingVotes ->
            DirVote.Phase.FETCH_VOTES
        !schedule.haveBuiltConsensus && nowEpochSec >= schedule.votingEnds ->
            DirVote.Phase.COMPUTE_CONSENSUS
        !schedule.haveFetchedMissingSignatures && nowEpochSec >= schedule.fetchMissingSignatures ->
            DirVote.Phase.FETCH_SIGNATURES
        !schedule.havePublishedConsensus && nowEpochSec >= schedule.intervalStarts ->
            DirVote.Phase.PUBLISH
        else -> DirVote.Phase.IDLE
    }

    fun pendingVotes(): Map<String, BandwidthVote.VoteDocument> = LinkedHashMap(votes)

    private val votes = LinkedHashMap<String, BandwidthVote.VoteDocument>()

    fun addVote(body: String, from: String = "local"): BandwidthVote.VoteDocument {
        val doc = BandwidthVote.parse(body)
        for (r in doc.routers) {
            val rsaTok = r.identityHex
            val ed = r.ed25519IdentityHex
            var keypinOk = true
            // Keypin expects raw SHA1 digests; only apply when identity looks like hex40.
            if (rsaTok != null && ed != null &&
                rsaTok.length == 40 && rsaTok.all { it in "0123456789abcdefABCDEF" } &&
                ed.length == 64 && ed.all { it in "0123456789abcdefABCDEF" }
            ) {
                fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                when (keypin.checkAndAdd(hex(rsaTok), hex(ed))) {
                    Keypin.Result.MISMATCH -> keypinOk = false
                    else -> Unit
                }
            }
            if (keypinOk && rsaTok != null && r.ip != null && r.orPort != null) {
                reachability.noteTarget(
                    ReachabilityTracker.Target(
                        identityHex = rsaTok.lowercase(),
                        ip = r.ip,
                        orPort = r.orPort,
                        ed25519Hex = ed,
                    ),
                )
            }
        }
        val id = doc.header.published ?: from
        votes[id + ":" + (doc.routers.firstOrNull()?.identityHex ?: from)] = doc
        return doc
    }

    fun clearVotes() {
        votes.clear()
    }

    fun loadGuardFractionFile(text: String): Int {
        val file = GuardFraction.parse(text)
        return GuardFraction.applyTo(guardFractions, file)
    }

    fun computeConsensusBody(nAuthorities: Int = votes.size): String {
        val collated = DirCollator.collate(votes.values.toList(), nAuthorities)
        val body = DirCollator.formatConsensusBody(collated)
        consCache.put(body)
        return body
    }

    /**
     * Sign [computeConsensusBody] with Ed25519 testing keys and emit detached + attached forms.
     */
    fun publishSigned(
        identityHex: String,
        privateKey: ByteArray,
        validAfter: String = "2020-01-01 00:00:00",
    ): Pair<String, String> {
        val body = computeConsensusBody()
        val sig = DetachedSignatures.signEd25519(body, identityHex, privateKey)
        val attached = DetachedSignatures.attachToConsensus(body, listOf(sig))
        val detached = DetachedSignatures.formatDetached(
            body,
            validAfter,
            validAfter,
            validAfter,
            listOf(sig),
        )
        return attached to detached
    }

    /**
     * Sign consensus with RSA authority cert signing key (dir-spec sha1 signature).
     */
    fun publishSignedRsa(
        authority: AuthorityCert.Material,
        sharedRandom: SharedRandom.Srv? = null,
        validAfter: String = "2020-01-01 00:00:00",
    ): Pair<String, String> {
        val collated = DirCollator.collate(votes.values.toList(), votes.size)
        val body = DirCollator.formatConsensusBody(collated, sharedRandom = sharedRandom)
        val sig = DetachedSignatures.signSha1Rsa(
            body,
            identityFingerprintHex = authority.identityFingerprint.toHex(),
            signingKeyDigestHex = authority.signingKeyDigest.toHex(),
            signingPrivateKey = authority.signing.private,
        )
        val attached = DetachedSignatures.attachToConsensus(body, listOf(sig))
        val detached = DetachedSignatures.formatDetached(
            body,
            validAfter,
            validAfter,
            validAfter,
            listOf(sig),
        )
        return attached to detached
    }
}
