package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DirVoteTest {
    @Test
    fun `schedule phases advance`() {
        val timing = DirVote.Timing(voteIntervalSec = 300, voteSeconds = 30, distSeconds = 30)
        val start = 1_000_000L
        val sched = DirVote.buildSchedule(timing, start)
        assertEquals(start - 60, sched.votingStarts)
        val phases = mutableListOf<String>()
        val actor = DirVoteActor(
            timing,
            sched,
            onVote = { phases += "vote" },
            onFetchVotes = { phases += "fetchV" },
            onComputeConsensus = { phases += "compute" },
            onFetchSignatures = { phases += "fetchS" },
            onPublish = { phases += "publish" },
        )
        // Before vote time — waits.
        val wait = actor.act(sched.votingStarts - 1)
        assertEquals(sched.votingStarts, wait)
        // Jump to publish time — all phases fire in one act.
        actor.act(start + 1)
        assertTrue(phases.contains("vote"))
        assertTrue(phases.contains("publish"))
    }

    @Test
    fun `consensus method majority`() {
        assertEquals(34, DirVote.preferredConsensusMethod(listOf(33, 34, 34, 35)))
    }

    @Test
    fun `addVote and collate`() {
        val timing = DirVote.Timing(300, 30, 30)
        val actor = DirVoteActor(timing, DirVote.buildSchedule(timing, 1000))
        actor.addVote(BandwidthVote.formatMinimalVote("A", "ID1", 100))
        actor.addVote(BandwidthVote.formatMinimalVote("A", "ID1", 200).replace("Bandwidth=200", "Bandwidth=200"))
        val body = actor.computeConsensusBody(nAuthorities = 2)
        assertTrue(body.contains("vote-status consensus"))
        assertTrue(body.contains("ID1"))
        assertTrue(body.contains("directory-footer"))
    }

    @Test
    fun `publishSignedRsa verifies with signing key`() {
        val timing = DirVote.Timing(300, 30, 30)
        val actor = DirVoteActor(timing, DirVote.buildSchedule(timing, 1000))
        actor.addVote(BandwidthVote.formatMinimalVote("A", "ID1", 150))
        val auth = AuthorityCert.generate(bits = 2048)
        val (attached, detached) = actor.publishSignedRsa(auth)
        assertTrue(attached.contains("directory-signature sha1"))
        assertTrue(detached.contains("directory-signature sha1"))
        val unsigned = attached.lineSequence()
            .takeWhile { !it.startsWith("directory-signature") }
            .joinToString("\n") + "\n"
        assertTrue(
            DetachedSignatures.verifySha1Rsa(
                unsigned,
                auth.signing.public,
                DetachedSignatures.parse(detached).signatures.first().signature,
            ),
        )
    }
}
