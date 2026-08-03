package org.kotlintor.pt

/**
 * Known Tor PT transport profiles (obfs4 / snowflake / meek_lite / webtunnel).
 * External binaries still provide the crypto; kotlin-tor owns lifecycle + SOCKS.
 */
enum class PtTransport(
    val wireName: String,
    val typicalExecNames: List<String>,
) {
    OBFS4("obfs4", listOf("obfs4proxy", "lyrebird")),
    SNOWFLAKE("snowflake", listOf("snowflake-client", "snowflake")),
    MEEK_LITE("meek_lite", listOf("meek-client", "obfs4proxy", "lyrebird")),
    WEBTUNNEL("webtunnel", listOf("webtunnel-client", "lyrebird")),
    SCRAMBLESUIT("scramblesuit", listOf("obfs4proxy")),
    ;

    companion object {
        fun parse(name: String): PtTransport? =
            entries.firstOrNull { it.wireName.equals(name, ignoreCase = true) }

        fun knownNames(): Set<String> = entries.mapTo(HashSet()) { it.wireName }
    }
}

/**
 * Per-transport CMETHOD endpoint (socks host:port) from PT stdout.
 */
data class PtCmethod(
    val transport: String,
    val protocol: String,
    val socksAddress: String,
)

/**
 * Validate Bridge-line args for known transports (lite allowlist).
 */
object PtBridgeArgs {
    private val OBFS4_KEYS = setOf("cert", "iat-mode")
    private val SNOWFLAKE_KEYS = setOf(
        "fingerprint", "url", "ice", "u", "utls-imitate", "ampcache", "fronts", "front",
    )
    private val MEEK_KEYS = setOf("url", "front", "utls-imitate")
    private val WEBTUNNEL_KEYS = setOf("url", "servername", "addr")

    fun parseArgs(bridgeLine: String): Map<String, String> {
        val out = linkedMapOf<String, String>()
        for (tok in bridgeLine.trim().split(Regex("\\s+"))) {
            val eq = tok.indexOf('=')
            if (eq > 0) out[tok.substring(0, eq)] = tok.substring(eq + 1)
        }
        return out
    }

    fun validate(transport: PtTransport, args: Map<String, String>): List<String> {
        val allowed = when (transport) {
            PtTransport.OBFS4 -> OBFS4_KEYS
            PtTransport.SNOWFLAKE -> SNOWFLAKE_KEYS
            PtTransport.MEEK_LITE -> MEEK_KEYS
            PtTransport.WEBTUNNEL -> WEBTUNNEL_KEYS
            PtTransport.SCRAMBLESUIT -> setOf("password")
        }
        return args.keys.filter { it !in allowed }.map { "unknown arg '$it' for ${transport.wireName}" }
    }

    fun requiredPresent(transport: PtTransport, args: Map<String, String>): List<String> {
        val need = when (transport) {
            PtTransport.OBFS4 -> listOf("cert")
            PtTransport.MEEK_LITE -> listOf("url")
            PtTransport.WEBTUNNEL -> listOf("url")
            else -> emptyList()
        }
        return need.filter { it !in args }.map { "missing required arg '$it' for ${transport.wireName}" }
    }
}
