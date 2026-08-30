package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.toHex
import org.kotlintor.util.u32be
import org.kotlintor.util.u64be
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Shared-random protocol (prop250 / C Tor `shared_random.h`).
 *
 * COMMIT = base64(TIMESTAMP || H(encoded_reveal))
 * REVEAL = base64(TIMESTAMP || RN)
 * hashed_reveal = SHA3-256(encoded_reveal ASCII, SR_REVEAL_BASE64_LEN)
 * SRV = SHA3-256("shared-random" | INT8(reveal_num) | INT4(version) |
 *                HASHED_REVEALS | previous_SRV)
 * where HASHED_REVEALS = SHA3-256(join(sorted fp_hex + encoded_reveal)).
 */
object SharedRandom {
    const val PROTO_VERSION: Int = 1
    const val SRV_TOKEN: String = "shared-random"
    const val RANDOM_NUMBER_LEN: Int = 32
    const val COMMIT_NS: String = "shared-rand-commit"

    /** `BASE64_LEN(40)` from Tor `binascii.h`. */
    const val REVEAL_BASE64_LEN: Int = 56
    const val COMMIT_BASE64_LEN: Int = 56

    enum class Phase { COMMIT, REVEAL }

    data class Srv(
        val numReveals: Long,
        val value: ByteArray,
    ) {
        init {
            require(value.size == 32)
        }

        fun encodeBase64(): String =
            Base64.getEncoder().encodeToString(value)

        fun toNsLine(key: String = "shared-rand-current-value"): String =
            "$key $numReveals ${encodeBase64()}"
    }

    data class Commit(
        val rsaIdentity: ByteArray,
        val commitTs: Long,
        val revealTs: Long,
        val randomNumber: ByteArray,
        val hashedReveal: ByteArray,
        val encodedReveal: String,
        val encodedCommit: String,
        var valid: Boolean = true,
    ) {
        init {
            require(rsaIdentity.size == 20)
            require(randomNumber.size == RANDOM_NUMBER_LEN)
            require(hashedReveal.size == 32)
            require(encodedReveal.length == REVEAL_BASE64_LEN)
            require(encodedCommit.length == COMMIT_BASE64_LEN)
        }

        val rsaIdentityHex: String get() = rsaIdentity.toHex().uppercase()

        fun voteLine(phase: Phase): String =
            when (phase) {
                Phase.COMMIT ->
                    "$COMMIT_NS $PROTO_VERSION sha3-256 $rsaIdentityHex $encodedCommit"
                Phase.REVEAL ->
                    "$COMMIT_NS $PROTO_VERSION sha3-256 $rsaIdentityHex $encodedCommit $encodedReveal"
            }

        /** C Tor `commit_encode`. */
        fun commitEncode(): String = encodedCommit

        /** C Tor `commit_has_reveal_value`. */
        fun commitHasRevealValue(): Boolean = encodedReveal.isNotEmpty()

        /** C Tor `commit_is_authoritative` — valid + reveal matches. */
        fun commitIsAuthoritative(): Boolean = valid && verifyRevealMatchesCommit(this)
    }

    /** C Tor `commit_decode` — parse commit/reveal base64 pair into [Commit] fields check. */
    fun commitDecode(encodedCommit: String, encodedReveal: String? = null): Boolean {
        if (encodedCommit.length != COMMIT_BASE64_LEN) return false
        if (encodedReveal != null && encodedReveal.length != REVEAL_BASE64_LEN) return false
        return try {
            Base64.getDecoder().decode(encodedCommit)
            if (encodedReveal != null) Base64.getDecoder().decode(encodedReveal)
            true
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    /** C Tor `commitments_are_the_same`. */
    fun commitmentsAreTheSame(a: Commit, b: Commit): Boolean =
        a.encodedCommit == b.encodedCommit && a.rsaIdentityHex == b.rsaIdentityHex

    /** C Tor `commit_encode` free function. */
    fun commitEncode(commit: Commit): String = commit.commitEncode()

    fun commitHasRevealValue(commit: Commit): Boolean = commit.commitHasRevealValue()

    fun commitIsAuthoritative(commit: Commit): Boolean = commit.commitIsAuthoritative()

    fun generateCommit(
        rsaIdentity: ByteArray,
        timestampEpochSec: Long = System.currentTimeMillis() / 1000,
        randomNumber: ByteArray = SecureRandomSource.nextBytes(RANDOM_NUMBER_LEN),
    ): Commit {
        require(rsaIdentity.size == 20)
        require(randomNumber.size == RANDOM_NUMBER_LEN)
        val revealRaw = u64be(timestampEpochSec) + randomNumber
        val encodedReveal = Base64.getEncoder().encodeToString(revealRaw)
        require(encodedReveal.length == REVEAL_BASE64_LEN) {
            "reveal b64 len ${encodedReveal.length} != $REVEAL_BASE64_LEN"
        }
        val hashedReveal = Digests.sha3_256(encodedReveal.toByteArray(Charsets.US_ASCII))
        val commitRaw = u64be(timestampEpochSec) + hashedReveal
        val encodedCommit = Base64.getEncoder().encodeToString(commitRaw)
        require(encodedCommit.length == COMMIT_BASE64_LEN)
        return Commit(
            rsaIdentity = rsaIdentity.copyOf(),
            commitTs = timestampEpochSec,
            revealTs = timestampEpochSec,
            randomNumber = randomNumber.copyOf(),
            hashedReveal = hashedReveal,
            encodedReveal = encodedReveal,
            encodedCommit = encodedCommit,
        )
    }

    fun verifyRevealMatchesCommit(commit: Commit): Boolean {
        val recomputed = Digests.sha3_256(commit.encodedReveal.toByteArray(Charsets.US_ASCII))
        return recomputed.contentEquals(commit.hashedReveal)
    }

    /**
     * Compute SRV from commits that have reveals. Sorts by [Commit.hashedReveal]
     * ascending (C Tor `compare_reveal_`).
     */
    fun computeSrv(commits: List<Commit>, previous: Srv? = null): Srv {
        val usable = commits.filter { it.valid && verifyRevealMatchesCommit(it) }
            .sortedWith { a, b ->
                val c = a.hashedReveal.compareUnsigned(b.hashedReveal)
                if (c != 0) c else a.rsaIdentityHex.compareTo(b.rsaIdentityHex)
            }
        val chunks = usable.map { it.rsaIdentityHex.lowercase() + it.encodedReveal }
        val joined = chunks.joinToString("")
        val hashedReveals = Digests.sha3_256(joined.toByteArray(Charsets.US_ASCII))
        val revealNum = usable.size.toLong()
        // msg size = SR_SRV_MSG_LEN + DIGEST256_LEN (always room for previous_SRV).
        val msg = ByteArray(SRV_TOKEN.length + 8 + 4 + 32 + 32)
        var o = 0
        val token = SRV_TOKEN.toByteArray(Charsets.US_ASCII)
        token.copyInto(msg, o); o += token.size
        u64be(revealNum).copyInto(msg, o); o += 8
        u32be(PROTO_VERSION.toLong()).copyInto(msg, o); o += 4
        hashedReveals.copyInto(msg, o); o += 32
        previous?.value?.copyInto(msg, o)
        val value = Digests.sha3_256(msg)
        return Srv(numReveals = revealNum, value = value)
    }

    /**
     * C Tor `get_majority_srv_from_votes` — majority SRV among vote SRV values.
     */
    fun getMajoritySrvFromVotes(srvs: List<Srv>): Srv? {
        if (srvs.isEmpty()) return null
        val majority = (srvs.size + 1) / 2
        val groups = srvs.groupBy { it.encodeBase64() }
        return groups.values.firstOrNull { it.size >= majority }?.first()
            ?: groups.values.maxByOrNull { it.size }?.first()
    }

    /** C Tor `reveal_encode` / `reveal_decode`. */
    fun revealEncode(revealTs: Long, randomNumber: ByteArray): String {
        require(randomNumber.size == RANDOM_NUMBER_LEN)
        val raw = ByteArray(8 + RANDOM_NUMBER_LEN)
        u64be(revealTs).copyInto(raw, 0)
        randomNumber.copyInto(raw, 8)
        return Base64.getEncoder().encodeToString(raw)
    }

    fun revealDecode(encodedReveal: String): Pair<Long, ByteArray>? {
        if (encodedReveal.length != REVEAL_BASE64_LEN) return null
        val raw = runCatching { Base64.getDecoder().decode(encodedReveal) }.getOrNull() ?: return null
        if (raw.size != 8 + RANDOM_NUMBER_LEN) return null
        var ts = 0L
        for (i in 0 until 8) ts = (ts shl 8) or (raw[i].toLong() and 0xff)
        return ts to raw.copyOfRange(8, raw.size)
    }

    @Volatile
    private var numSrvAgreements: Int = 0

    /** C Tor `set_num_srv_agreements`. */
    fun setNumSrvAgreements(n: Int) {
        numSrvAgreements = n.coerceAtLeast(0)
    }

    fun getNumSrvAgreements(): Int = numSrvAgreements

    /** C Tor `save_commit_to_state` / `save_commit_during_reveal_phase`. */
    fun saveCommitToState(state: State, commit: Commit) {
        state.put(commit)
    }

    fun saveCommitDuringRevealPhase(state: State, commit: Commit): Boolean {
        if (!commit.commitHasRevealValue()) return false
        state.put(commit)
        return true
    }

    /** In-memory commit map keyed by RSA identity hex (dirauth testing). */
    class State {
        private val commits = ConcurrentHashMap<String, Commit>()
        @Volatile var previousSrv: Srv? = null
        @Volatile var currentSrv: Srv? = null

        fun put(commit: Commit) {
            commits[commit.rsaIdentityHex] = commit
        }

        fun get(identityHex: String): Commit? = commits[identityHex.uppercase()]
            ?: commits[identityHex.lowercase()]
            ?: commits.entries.firstOrNull { it.key.equals(identityHex, ignoreCase = true) }?.value

        fun all(): List<Commit> = commits.values.toList()

        fun deleteAll() {
            commits.clear()
        }

        fun remove(identityHex: String) {
            commits.keys.filter { it.equals(identityHex, ignoreCase = true) }.forEach { commits.remove(it) }
        }

        fun recompute() {
            currentSrv = computeSrv(all(), previousSrv)
        }

        /** Persist current/previous SRV to disk (C Tor `sr_state`). */
        fun save(path: java.nio.file.Path) {
            val lines = buildList {
                previousSrv?.let { add("previous ${it.numReveals} ${it.encodeBase64()}") }
                currentSrv?.let { add("current ${it.numReveals} ${it.encodeBase64()}") }
                for (c in all()) {
                    add("commit ${c.rsaIdentityHex} ${c.encodedCommit} ${c.encodedReveal}")
                }
            }
            java.nio.file.Files.createDirectories(path.parent)
            java.nio.file.Files.writeString(path, lines.joinToString("\n") + "\n")
        }

        fun load(path: java.nio.file.Path) {
            if (!java.nio.file.Files.isRegularFile(path)) return
            commits.clear()
            previousSrv = null
            currentSrv = null
            for (raw in java.nio.file.Files.readString(path).lineSequence()) {
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                val p = line.split(' ')
                when (p[0]) {
                    "previous" -> if (p.size >= 3) {
                        previousSrv = Srv(p[1].toLong(), Base64.getDecoder().decode(p[2]))
                    }
                    "current" -> if (p.size >= 3) {
                        currentSrv = Srv(p[1].toLong(), Base64.getDecoder().decode(p[2]))
                    }
                    "commit" -> if (p.size >= 4) {
                        val id = org.kotlintor.util.hexToBytes(p[1])
                        if (id.size == 20 && p[2].length == COMMIT_BASE64_LEN && p[3].length == REVEAL_BASE64_LEN) {
                            val revealRaw = runCatching { Base64.getDecoder().decode(p[3]) }.getOrNull()
                            if (revealRaw != null && revealRaw.size == 8 + RANDOM_NUMBER_LEN) {
                                put(
                                    Commit(
                                        rsaIdentity = id,
                                        commitTs = 0,
                                        revealTs = 0,
                                        randomNumber = revealRaw.copyOfRange(8, revealRaw.size),
                                        hashedReveal = Digests.sha3_256(p[3].toByteArray(Charsets.US_ASCII)),
                                        encodedReveal = p[3],
                                        encodedCommit = p[2],
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    /** C Tor `should_keep_commit`. */
    fun shouldKeepCommit(commit: Commit): Boolean =
        commit.valid && verifyRevealMatchesCommit(commit)

    /** C Tor `sr_act_post_consensus` — rotate previous←current and recompute. */
    fun srActPostConsensus(state: State) {
        state.previousSrv = state.currentSrv
        state.recompute()
    }

    /** C Tor `sr_commit_free_`. */
    fun srCommitFree_(commit: Commit?): Commit? = null

    /** C Tor `sr_compute_srv`. */
    fun srComputeSrv(commits: List<Commit>, previous: Srv? = null): Srv =
        computeSrv(commits, previous)

    /** C Tor `sr_generate_our_commit`. */
    fun srGenerateOurCommit(rsaIdentity: ByteArray): Commit = generateCommit(rsaIdentity)

    /** C Tor `sr_get_string_for_consensus`. */
    fun srGetStringForConsensus(current: Srv?, previous: Srv? = null): String = buildString {
        previous?.let { append(it.toNsLine("shared-rand-previous-value")) }
        current?.let { append(it.toNsLine("shared-rand-current-value")) }
    }

    /** C Tor `sr_get_string_for_vote`. */
    fun srGetStringForVote(commit: Commit, phase: Phase): String = commit.voteLine(phase)

    /** C Tor `sr_handle_received_commits`. */
    fun srHandleReceivedCommits(state: State, commits: List<Commit>): Int {
        var n = 0
        for (c in commits) {
            if (!shouldKeepCommit(c) && !c.commitHasRevealValue()) continue
            state.put(c)
            n++
        }
        return n
    }

    /** C Tor `sr_init`. */
    fun srInit(): State = State()

    /** C Tor `sr_parse_commit` — parse one vote commit line. */
    fun srParseCommit(line: String): Commit? =
        DirVote.dirvoteParseSrCommits(line).firstOrNull()

    /** C Tor `sr_save_and_cleanup`. */
    fun srSaveAndCleanup(state: State, path: java.nio.file.Path) {
        state.recompute()
        state.save(path)
        state.deleteAll()
    }

    /** C Tor `sr_srv_dup`. */
    fun srSrvDup(srv: Srv): Srv = Srv(srv.numReveals, srv.value.copyOf())

    /** C Tor `verify_commit_and_reveal`. */
    fun verifyCommitAndReveal(commit: Commit): Boolean = verifyRevealMatchesCommit(commit)

    private fun ByteArray.compareUnsigned(other: ByteArray): Int {
        val n = minOf(size, other.size)
        for (i in 0 until n) {
            val a = this[i].toInt() and 0xff
            val b = other[i].toInt() and 0xff
            if (a != b) return a - b
        }
        return size - other.size
    }
}
