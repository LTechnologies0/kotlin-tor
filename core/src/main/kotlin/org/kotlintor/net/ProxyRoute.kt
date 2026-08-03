package org.kotlintor.net

/**
 * Destination + isolation metadata produced by a local proxy frontend,
 * consumed by TorClient.connect / circuit isolation.
 */
data class TorRouteRequest(
    val endpoint: NetEndpoint,
    /** IsolateSOCKSAuth / X-Tor-Stream-Isolation / Proxy-Authorization user. */
    val isolationKey: String? = null,
    val clientAddr: String? = null,
    val familyPreference: FamilyPreference = FamilyPreference.Ipv4Preferred,
    val optimisticData: Boolean = true,
    /** Protocol that produced this request (for logging / policy). */
    val via: ProxyKind = ProxyKind.Raw,
)

enum class ProxyKind {
    Raw,
    Socks4,
    Socks5,
    HttpConnect,
    HttpAbsolute,
    TlsSni,
    Transparent,
    DnsTcp,
}

enum class Socks5Command(val code: Int) {
    Connect(0x01),
    Bind(0x02),
    UdpAssociate(0x03),
    ;

    companion object {
        fun from(code: Int): Socks5Command? = entries.firstOrNull { it.code == code }
    }
}

enum class Socks5Reply(val code: Int) {
    Succeeded(0x00),
    GeneralFailure(0x01),
    NotAllowed(0x02),
    NetworkUnreachable(0x03),
    HostUnreachable(0x04),
    ConnectionRefused(0x05),
    TtlExpired(0x06),
    CommandNotSupported(0x07),
    AddressTypeNotSupported(0x08),
}

/**
 * Pluggable frontend: parse bytes from a local [BytePipe], emit [TorRouteRequest],
 * then leave the pipe in tunnel mode for [StreamRelay].
 */
fun interface ProxyFrontend {
    suspend fun negotiate(local: BytePipe): TorRouteRequest?
}

