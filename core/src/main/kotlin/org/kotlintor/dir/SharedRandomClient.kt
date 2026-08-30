package org.kotlintor.dir

/**
 * Client-side shared random values from consensus (C Tor `shared_random_client.c`).
 *
 * Inventory: `L1:feature/hs_common/shared_random_client.c`
 *
 * Protocol helpers: [SharedRandom].
 */
object SharedRandomClient {
    const val N_ROUNDS: Int = 12
    const val N_PHASES: Int = 2

    data class ParsedSrv(
        val numReveals: Int,
        val valueBase64: String,
        val value: ByteArray,
    )

    /** Parse `shared-rand-current-value N BASE64` / previous from consensus text. */
    fun parseFromConsensus(text: String): Pair<ParsedSrv?, ParsedSrv?> {
        var current: ParsedSrv? = null
        var previous: ParsedSrv? = null
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            when {
                line.startsWith("shared-rand-current-value ") ->
                    current = parseSrvLine(line.removePrefix("shared-rand-current-value ").trim())
                line.startsWith("shared-rand-previous-value ") ->
                    previous = parseSrvLine(line.removePrefix("shared-rand-previous-value ").trim())
            }
        }
        return current to previous
    }

    fun parseSrvLine(args: String): ParsedSrv? {
        val p = args.split(Regex("\\s+"))
        if (p.size < 2) return null
        val n = p[0].toIntOrNull() ?: return null
        val b64 = p[1]
        val value = try {
            java.util.Base64.getDecoder().decode(b64)
        } catch (_: Exception) {
            return null
        }
        if (value.size != 32) return null
        return ParsedSrv(n, b64, value)
    }

    fun getCurrent(nsText: String): ParsedSrv? = parseFromConsensus(nsText).first
    fun getPrevious(nsText: String): ParsedSrv? = parseFromConsensus(nsText).second

    fun forControl(srv: ParsedSrv?): String =
        if (srv == null) "" else "${srv.numReveals} ${srv.valueBase64}"

    /** Voting interval helper (seconds); default 1h when unknown. */
    fun votingIntervalSec(params: Map<String, String> = emptyMap()): Int =
        params["AuthDirVoteInterval"]?.toIntOrNull()
            ?: params["V3AuthVotingInterval"]?.toIntOrNull()
            ?: 3600

    fun phaseDurationSec(voteIntervalSec: Int = 3600): Int =
        voteIntervalSec * N_ROUNDS

    fun protocolRunDurationSec(voteIntervalSec: Int = 3600): Int =
        phaseDurationSec(voteIntervalSec) * N_PHASES

    fun startOfCurrentProtocolRun(nowEpochSec: Long, voteIntervalSec: Int = 3600): Long {
        val run = protocolRunDurationSec(voteIntervalSec).toLong()
        return (nowEpochSec / run) * run
    }

    fun startOfPreviousProtocolRun(nowEpochSec: Long, voteIntervalSec: Int = 3600): Long =
        startOfCurrentProtocolRun(nowEpochSec, voteIntervalSec) -
            protocolRunDurationSec(voteIntervalSec)

    fun protoVersion(): Int = SharedRandom.PROTO_VERSION
}
