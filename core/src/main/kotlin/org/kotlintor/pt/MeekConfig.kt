package org.kotlintor.pt

/**
 * Meek / domain-fronting configuration hints for Moat and bridge fetch.
 *
 * Actual meek traffic still requires an external meek_lite PT binary via
 * [ClientTransportPlugin]; this documents the Tor Project defaults so apps
 * can wire PT args without hardcoding.
 */
object MeekConfig {
    const val TRANSPORT = "meek_lite"
    const val DEFAULT_FRONT = BridgeDbClient.DEFAULT_MEEK_FRONT
    val defaultMoatRoot: String
        get() = BridgeDbClient.DEFAULT_MOAT_SETTINGS.substringBefore("/moat/")

    /** Example Bridge line using meek_lite (placeholders for operator-supplied bridge). */
    fun sampleBridgeLine(
        bridgeHostPort: String,
        fingerprint: String,
        url: String = BridgeDbClient.DEFAULT_MEEK_URL,
        front: String = DEFAULT_FRONT,
    ): String = "meek_lite $bridgeHostPort $fingerprint url=$url front=$front"

    fun clientTransportPluginLine(pathToMeek: String): String =
        "ClientTransportPlugin meek_lite exec $pathToMeek"
}
