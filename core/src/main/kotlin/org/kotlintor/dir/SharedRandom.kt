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
    }

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

    /** In-memory commit map keyed by RSA identity hex (dirauth testing). */
    class State {
        private val commits = ConcurrentHashMap<String, Commit>()
        @Volatile var previousSrv: Srv? = null
        @Volatile var currentSrv: Srv? = null

        fun put(commit: Commit) {
            commits[commit.rsaIdentityHex] = commit
        }

        fun all(): List<Commit> = commits.values.toList()

        fun recompute() {
            currentSrv = computeSrv(all(), previousSrv)
        }

        /** Persist current/previous SRV to disk (C Tor `sr_state` lite). */
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
