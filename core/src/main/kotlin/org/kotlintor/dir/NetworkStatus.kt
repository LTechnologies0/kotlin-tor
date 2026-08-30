package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Networkstatus document helpers (C Tor `networkstatus.c`).
 *
 * Inventory: `L1:feature/nodelist/networkstatus.c`
 *
 * Consensus parse/validity lives in [Consensus] / [ConsensusParser]; this
 * object exposes the C Tor-shaped entry surface used by elevation tests.
 */
object NetworkStatus {
    const val C_TOR_UNIT: String = "networkstatus.c"

    fun isValidAt(consensus: Consensus, now: java.time.Instant = java.time.Instant.now()): Boolean =
        consensus.isValidAt(now)

    fun param(consensus: Consensus, name: String, default: Long): Long =
        consensus.param(name, default)

    fun relayCount(consensus: Consensus): Int = consensus.relays.size

    fun findByNickname(consensus: Consensus, nickname: String): RouterStatus? =
        consensus.relays.firstOrNull { it.nickname.equals(nickname, ignoreCase = true) }

    /** C Tor `compare_digest_to_routerstatus_entry` — memcmp on RSA identity digest. */
    fun compareDigestToRouterstatusEntry(digest: ByteArray, rs: RouterStatus): Int {
        require(digest.size == rs.identity.size)
        for (i in digest.indices) {
            val a = digest[i].toInt() and 0xff
            val b = rs.identity[i].toInt() and 0xff
            if (a != b) return a - b
        }
        return 0
    }

    /** C Tor `compare_digest_to_vote_routerstatus_entry`. */
    fun compareDigestToVoteRouterstatusEntry(digest: ByteArray, rs: RouterStatus): Int =
        compareDigestToRouterstatusEntry(digest, rs)

    /** C Tor `client_would_use_router` — Running + EXTEND2 (proto Link/Relay). */
    fun clientWouldUseRouter(rs: RouterStatus): Boolean {
        if (!rs.isRunning) return false
        // C Tor checks router supports EXTEND2; approximate via Link/Relay proto or Running+Valid.
        if (rs.supportsProto("Relay", 2) || rs.supportsProto("Link", 4)) return true
        return "Valid" in rs.flags
    }

    /** C Tor `consensus_is_waiting_for_certs`. */
    fun consensusIsWaitingForCerts(): Boolean = AuthCert.authorityCertsWaiting()

    data class DocumentSignature(
        val identityHex: String,
        val signingKeyDigestHex: String,
        val signature: ByteArray,
        val algorithm: String = "sha1",
    )

    /** C Tor `document_signature_dup`. */
    fun documentSignatureDup(sig: DocumentSignature): DocumentSignature =
        sig.copy(signature = sig.signature.copyOf())

    /** C Tor `document_signature_free_`. */
    fun documentSignatureFree_(sig: DocumentSignature?): DocumentSignature? = null

    /** C Tor `getinfo_helper_networkstatus` — thin status string. */
    fun getinfoHelperNetworkstatus(consensus: Consensus?): String {
        if (consensus == null) return "networkstatus/unavailable"
        return "networkstatus/relays=${consensus.relays.size} valid=${isValidAt(consensus)}"
    }

    @Volatile private var consensusDownloading: Boolean = false
    @Volatile private var consensusDownloadFailures: Int = 0
    @Volatile private var cachedConsensus: Consensus? = null
    private val voters = ConcurrentHashMap<String, String>()

    /** C Tor `networkstatus_free_all`. */
    fun networkstatusFreeAll() {
        consensusDownloading = false
        consensusDownloadFailures = 0
        cachedConsensus = null
        voters.clear()
        AuthCert.clearWaiting()
    }

    /**
     * C Tor `networkstatus_check_consensus_signature` —
     * structural gate: document must contain ≥1 `directory-signature` block.
     * Full authority-cert RSA/Ed verify is [DetachedSignatures] / dirauth path;
     * this does not invent a green quorum from a bare network-status preamble.
     */
    fun networkstatusCheckConsensusSignature(consensus: Consensus): Boolean {
        if (consensus.raw.isBlank()) return false
        return consensus.raw.contains("directory-signature")
    }

    /**
     * C Tor `networkstatus_check_document_signature` —
     * require non-empty identity + signature bytes (crypto check needs cert elsewhere).
     */
    fun networkstatusCheckDocumentSignature(sig: DocumentSignature): Boolean =
        sig.signature.isNotEmpty() &&
            sig.identityHex.isNotBlank() &&
            sig.signingKeyDigestHex.isNotBlank()

    /** C Tor `networkstatus_consensus_can_use_multiple_directories`. */
    fun networkstatusConsensusCanUseMultipleDirectories(): Boolean = true

    /** C Tor `networkstatus_consensus_download_failed`. */
    fun networkstatusConsensusDownloadFailed() {
        consensusDownloading = false
        consensusDownloadFailures++
    }

    /** C Tor `networkstatus_consensus_is_already_downloading`. */
    fun networkstatusConsensusIsAlreadyDownloading(): Boolean = consensusDownloading

    fun networkstatusNoteConsensusDownloadStart() {
        consensusDownloading = true
    }

    /** C Tor `networkstatus_consensus_reasonably_live`. */
    fun networkstatusConsensusReasonablyLive(
        consensus: Consensus,
        now: java.time.Instant = java.time.Instant.now(),
    ): Boolean {
        val skew = java.time.Duration.ofHours(24)
        return !now.isBefore(consensus.validAfter.minus(skew)) &&
            now.isBefore(consensus.validUntil.plus(skew))
    }

    /** C Tor `networkstatus_is_live`. */
    fun networkstatusIsLive(
        consensus: Consensus,
        now: java.time.Instant = java.time.Instant.now(),
    ): Boolean = isValidAt(consensus, now)

    /** C Tor `networkstatus_get_bw_weight`. */
    fun networkstatusGetBwWeight(consensus: Consensus, name: String, default: Long = 0): Long =
        consensus.param(name, default)

    /** C Tor `networkstatus_get_flavor_name`. */
    fun networkstatusGetFlavorName(flavor: Int): String =
        when (flavor) {
            0 -> "ns"
            1 -> "microdesc"
            else -> "unknown"
        }

    /** C Tor `networkstatus_get_overridable_param`. */
    fun networkstatusGetOverridableParam(
        consensus: Consensus,
        name: String,
        default: Long,
    ): Long = consensus.param(name, default)

    /** C Tor `networkstatus_get_weight_scale_param`. */
    fun networkstatusGetWeightScaleParam(consensus: Consensus): Long =
        consensus.param("bwweightscale", 10000)

    /** C Tor `networkstatus_get_voter_by_id`. */
    fun networkstatusGetVoterById(idHex: String): String? = voters[idHex.lowercase()]

    fun networkstatusNoteVoter(idHex: String, nickname: String) {
        voters[idHex.lowercase()] = nickname
    }

    /** C Tor `networkstatus_get_voter_sig_by_alg`. */
    fun networkstatusGetVoterSigByAlg(
        sigs: List<DocumentSignature>,
        alg: String,
    ): DocumentSignature? = sigs.firstOrNull { it.algorithm.equals(alg, ignoreCase = true) }

    /** C Tor `networkstatus_getinfo_by_purpose`. */
    fun networkstatusGetinfoByPurpose(purpose: String): String =
        "networkstatus/purpose/$purpose"

    /** C Tor `networkstatus_getinfo_helper_single`. */
    fun networkstatusGetinfoHelperSingle(rs: RouterStatus): String =
        "${rs.nickname} ${rs.fingerprintHex}"

    /** C Tor `networkstatus_map_cached_consensus`. */
    fun networkstatusMapCachedConsensus(consensus: Consensus?) {
        cachedConsensus = consensus
    }

    fun networkstatusCachedConsensus(): Consensus? = cachedConsensus

    /** C Tor `networkstatus_note_certs_arrived`. */
    fun networkstatusNoteCertsArrived() {
        AuthCert.clearWaiting()
    }
}
