package org.kotlintor.dir

class MultiAuthNetwork(
    private val peers: List<DirAuthPublishLoop>,
) {
    init {
        require(peers.isNotEmpty())
    }

    fun startAll() = peers.forEach { it.start() }
    fun stopAll() = peers.forEach { it.stop() }

    /** Push [voteBody] from [fromFp] to every peer except the originator. */
    fun gossipVote(voteBody: String, fromFp: String) {
        for (p in peers) {
            p.addPeerVote(voteBody, fromFp)
        }
    }

    fun publishAll(): List<Pair<String, String>> =
        peers.mapNotNull { it.publishNow() }

    fun gossipHttp(
        httpPeers: List<Pair<String, Int>>,
        voteBody: String,
        fromFp: String,
    ): List<DirAuthVoteGossip.Result> {
        return kotlinx.coroutines.runBlocking {
            DirAuthVoteGossip.gossipToPeers(httpPeers, voteBody, fromFp)
        }
    }

    suspend fun gossipHttpSuspend(
        httpPeers: List<Pair<String, Int>>,
        voteBody: String,
        fromFp: String,
    ): List<DirAuthVoteGossip.Result> =
        DirAuthVoteGossip.gossipToPeers(httpPeers, voteBody, fromFp)

    fun quorumSatisfied(detachedBodies: List<String>, known: Set<String>): Boolean {
        val ids = detachedBodies.flatMap { DetachedSignatures.parse(it).signatures.map { s -> s.identityHex } }
        return DirAuthQuorum.hasQuorum(ids, known, known.size.coerceAtLeast(1))
    }
}
