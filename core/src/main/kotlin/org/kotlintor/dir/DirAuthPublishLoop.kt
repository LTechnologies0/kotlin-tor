package org.kotlintor.dir

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.nio.file.Path
import org.kotlintor.util.toHex

/**
 * Live directory-authority act loop (C Tor `dirvote_act` + bridgeauth dump).
 *
 * Runs [DirVoteActor] phases on a schedule, optionally collecting votes from
 * peer authorities until [DirAuthQuorum] is satisfied, then publishes consensus
 * and bridge status to [dataDir].
 */
class DirAuthPublishLoop(
    private val scope: CoroutineScope,
    private val dataDir: Path,
    private val timing: DirVote.Timing,
    private val knownAuthorities: Set<String>,
    private val localAuthority: AuthorityCert.Material? = null,
    private val onPublish: (attached: String, detached: String) -> Unit = { _, _ -> },
) {
    private var job: Job? = null
    val actor: DirVoteActor = DirVoteActor(
        timing = timing,
        schedule = DirVote.buildSchedule(timing, DirVote.nextValidAfter(timing, System.currentTimeMillis() / 1000)),
        onPublish = { publishNow() },
        consDiffMgr = ConsDiffMgr(storeDir = dataDir.resolve("diff-cache")),
    )

    private val bridgeStatuses = ArrayList<BridgeAuth.BridgeStatus>()
    private val peerDetached = ArrayList<String>()

    fun noteBridge(status: BridgeAuth.BridgeStatus) {
        synchronized(bridgeStatuses) {
            bridgeStatuses.removeAll { it.identityHex.equals(status.identityHex, true) }
            bridgeStatuses += status
        }
    }

    /** Ingest a peer authority's detached-signatures document for quorum merge. */
    fun notePeerDetached(detachedBody: String) {
        synchronized(peerDetached) {
            peerDetached += detachedBody
        }
    }

    fun start() {
        if (job != null) return
        job = scope.launch {
            while (isActive) {
                val now = System.currentTimeMillis() / 1000
                val next = actor.act(now)
                val wakeIn = ((next - now).coerceAtLeast(1) * 1000L).coerceAtMost(60_000L)
                delay(wakeIn)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    fun addPeerVote(body: String, from: String) {
        actor.addVote(body, from)
    }

    /** Attach an HTTP [DirAuthVoteInbox] so DirPort POSTs feed the vote actor. */
    fun attachVoteInbox(inbox: DirAuthVoteInbox) {
        inbox.onVote { from, body -> addPeerVote(body, from) }
    }

    /** Attach detached-signature inbox (POST `/tor/post/consensus-signature`). */
    fun attachSigInbox(inbox: DirAuthSigInbox) {
        inbox.onSig { _, body -> notePeerDetached(body) }
    }

    fun publishNow(): Pair<String, String>? {
        val auth = localAuthority ?: return null
        val (attachedLocal, detachedLocal) = actor.publishSignedRsa(auth)
        val peers = synchronized(peerDetached) { peerDetached.toList() }
        val merged = if (peers.isEmpty()) {
            DetachedSignatures.parse(detachedLocal)
        } else {
            MultiAuthQuorumSession(listOf(auth), dataDir = null).mergeDetached(
                listOf(detachedLocal) + peers,
            )
        }
        val known = knownAuthorities.map { it.lowercase() }.toSet()
        val quorum = DirAuthQuorum.fromDetached(merged, known)
        val attached = if (peers.isEmpty()) {
            attachedLocal
        } else {
            DetachedSignatures.attachToConsensus(
                // Body is everything before first directory-signature in attachedLocal
                attachedLocal.substringBefore("directory-signature ").trimEnd() + "\n",
                merged.signatures,
            )
        }
        val detached = DetachedSignatures.formatDetached(
            body = attachedLocal.substringBefore("directory-signature ").trimEnd() + "\n",
            validAfter = merged.validAfter ?: "2020-01-01 00:00:00",
            freshUntil = merged.freshUntil ?: merged.validAfter ?: "2020-01-01 00:00:00",
            validUntil = merged.validUntil ?: merged.validAfter ?: "2020-01-01 00:00:00",
            signatures = merged.signatures,
        )
        if (!quorum) {
            // Still write locally; quorum incomplete until more peer sigs arrive.
        }
        java.nio.file.Files.createDirectories(dataDir)
        java.nio.file.Files.writeString(dataDir.resolve("cached-consensus"), attached)
        java.nio.file.Files.writeString(dataDir.resolve("cached-consensus-diff"), detached)
        dumpBridges()
        onPublish(attached, detached)
        return attached to detached
    }

    fun dumpBridges() {
        val list = synchronized(bridgeStatuses) { bridgeStatuses.toList() }
        val body = BridgeAuth.formatNetworkstatusBridges(
            bridges = list,
            fingerprintHex = localAuthority?.identityFingerprint?.toHex(),
        )
        BridgeAuth.dumpToFile(dataDir, body)
    }

    fun hasPublishQuorum(detachedBody: String): Boolean {
        val known = knownAuthorities.map { it.lowercase() }.toSet()
        return DirAuthQuorum.fromDetached(DetachedSignatures.parse(detachedBody), known)
    }
}
