package org.kotlintor.dir

/**
 * Vote / bandwidth collation (C Tor `dircollate.c`).
 *
 * Inventory: `L1:feature/dirauth/dircollate.c`
 *
 * Implementation: [DirCollator].
 */
object DirCollate {
    fun collate(
        votes: List<BandwidthVote.VoteDocument>,
        nAuthorities: Int = votes.size,
    ) = DirCollator.collate(votes, nAuthorities)

    fun formatConsensusBody(
        routers: List<DirCollator.CollatedRouter>,
        sharedRandom: SharedRandom.Srv? = null,
        previousSharedRandom: SharedRandom.Srv? = null,
    ) = DirCollator.formatConsensusBody(routers, sharedRandom, previousSharedRandom)

    /** C Tor `dircollator_new`. */
    fun dircollatorNew(nVotes: Int = 0, nAuthorities: Int = nVotes): Dircollator =
        Dircollator(nAuthorities = nAuthorities.coerceAtLeast(0))

    /** C Tor `dircollator_free_`. */
    fun dircollatorFree_(dc: Dircollator?): Dircollator? {
        dc?.clear()
        return null
    }

    /** C Tor `dircollator_add_vote`. */
    fun dircollatorAddVote(dc: Dircollator, vote: BandwidthVote.VoteDocument) {
        dc.addVote(vote)
    }

    /** C Tor `dircollator_collate`. */
    fun dircollatorCollate(dc: Dircollator, consensusMethod: Int = DirVote.MIN_SUPPORTED_CONSENSUS_METHOD) {
        dc.collate(consensusMethod)
    }

    /** C Tor `dircollator_n_routers`. */
    fun dircollatorNRouters(dc: Dircollator): Int = dc.nRouters()

    /** C Tor `dircollator_get_votes_for_router`. */
    fun dircollatorGetVotesForRouter(dc: Dircollator, identityHex: String): List<BandwidthVote.RouterBandwidth> =
        dc.votesForRouter(identityHex)
}

/**
 * Mutable collator instance (C Tor `dircollator_t`).
 */
class Dircollator(
    val nAuthorities: Int = 0,
) {
    private val votes = ArrayList<BandwidthVote.VoteDocument>()
    private var collated: List<DirCollator.CollatedRouter> = emptyList()
    private val byIdentity = LinkedHashMap<String, MutableList<BandwidthVote.RouterBandwidth>>()

    fun addVote(vote: BandwidthVote.VoteDocument) {
        votes += vote
        for (r in vote.routers) {
            val id = r.identityHex ?: continue
            byIdentity.getOrPut(id.uppercase()) { mutableListOf() }.add(r)
        }
    }

    fun collate(consensusMethod: Int = DirVote.MIN_SUPPORTED_CONSENSUS_METHOD) {
        // consensusMethod reserved for method-specific collation rules
        collated = DirCollator.collate(votes, nAuthorities = if (nAuthorities > 0) nAuthorities else votes.size)
    }

    fun nRouters(): Int = collated.size

    fun votesForRouter(identityHex: String): List<BandwidthVote.RouterBandwidth> =
        byIdentity[identityHex.uppercase()]?.toList() ?: emptyList()

    fun clear() {
        votes.clear()
        collated = emptyList()
        byIdentity.clear()
    }

    fun result(): List<DirCollator.CollatedRouter> = collated
}
