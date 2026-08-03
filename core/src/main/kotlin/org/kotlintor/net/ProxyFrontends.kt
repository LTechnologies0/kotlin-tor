package org.kotlintor.net

/**
 * Pushback buffer over [BytePipe] so handshake parsers can read exact RFC layouts
 * and leave the remainder for the tunnel splice.
 */
class BufferedBytePipe(private val inner: BytePipe) : BytePipe {
    private val push = ArrayList<Byte>()

    override val bytesRead: Long get() = inner.bytesRead
    override val bytesWritten: Long get() = inner.bytesWritten

    override fun isClosed(): Boolean = inner.isClosed()

    override suspend fun close() = inner.close()

    fun pushFront(bytes: ByteArray) {
        for (i in bytes.indices.reversed()) {
            push.add(0, bytes[i])
        }
    }

    override suspend fun read(dst: ByteArray, offset: Int, length: Int): Int {
        if (push.isNotEmpty()) {
            val n = minOf(length, push.size)
            for (i in 0 until n) {
                dst[offset + i] = push.removeAt(0)
            }
            return n
        }
        return inner.read(dst, offset, length)
    }

    override suspend fun write(src: ByteArray, offset: Int, length: Int) =
        inner.write(src, offset, length)

    suspend fun readFully(n: Int): ByteArray {
        val out = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = read(out, got, n - got)
            if (r < 0) error("EOF after $got/$n")
            got += r
        }
        return out
    }

    suspend fun readByte(): Int {
        val b = ByteArray(1)
        val n = read(b)
        if (n < 0) return -1
        return b[0].toInt() and 0xff
    }

    /** Read until CRLFCRLF or [max] bytes (HTTP headers). */
    suspend fun readHttpHead(max: Int = 64 * 1024): ByteArray {
        val acc = ArrayList<Byte>()
        while (acc.size < max) {
            val b = readByte()
            if (b < 0) break
            acc.add(b.toByte())
            if (acc.size >= 4) {
                val n = acc.size
                if (acc[n - 4] == '\r'.code.toByte() && acc[n - 3] == '\n'.code.toByte() &&
                    acc[n - 2] == '\r'.code.toByte() && acc[n - 1] == '\n'.code.toByte()
                ) {
                    break
                }
            }
        }
        return acc.toByteArray()
    }
}

/** RFC 1928 + 1929 SOCKS5 negotiate (CONNECT / BIND / UDP ASSOCIATE). */
suspend fun negotiateSocks5(
    local: BufferedBytePipe,
    preferUserPass: Boolean = true,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): Socks5Outcome? {
    val ver = local.readByte()
    if (ver != Socks5Codec.VERSION) return null
    val nmethods = local.readByte()
    if (nmethods < 0) return null
    val methods = local.readFully(nmethods)
    val offer = Socks5Codec.MethodOffer(methods.map { it.toInt() and 0xff })
    val selected = Socks5Codec.selectMethod(offer, preferUserPass)
    local.write(Socks5Codec.encodeMethodSelect(selected))
    if (selected == Socks5Codec.AUTH_NO_ACCEPTABLE) return null

    var isolation: String? = null
    if (selected == Socks5Codec.AUTH_USERPASS) {
        val uv = local.readByte()
        if (uv != Socks5Codec.USERPASS_VERSION) return null
        val ulen = local.readByte()
        val user = local.readFully(ulen).toString(Charsets.UTF_8)
        val plen = local.readByte()
        local.readFully(plen)
        isolation = user
        local.write(Socks5Codec.encodeUserPassStatus(true))
    }

    if (local.readByte() != Socks5Codec.VERSION) return null
    val cmd = local.readByte()
    local.readByte() // rsv
    val atyp = local.readByte()
    val endpoint = when (atyp) {
        Socks5Codec.ATYP_IPV4 -> {
            val addr = local.readFully(4)
            val port = (local.readByte() shl 8) or local.readByte()
            NetEndpoint.Ipv4(addr, port)
        }
        Socks5Codec.ATYP_DOMAIN -> {
            val len = local.readByte()
            val name = local.readFully(len).toString(Charsets.UTF_8)
            val port = (local.readByte() shl 8) or local.readByte()
            NetEndpoint.Domain(name, port)
        }
        Socks5Codec.ATYP_IPV6 -> {
            val addr = local.readFully(16)
            val port = (local.readByte() shl 8) or local.readByte()
            NetEndpoint.Ipv6(addr, port)
        }
        else -> {
            local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.AddressTypeNotSupported)))
            return null
        }
    }
    return when (Socks5Command.from(cmd)) {
        Socks5Command.Connect -> Socks5Outcome.Connect(
            TorRouteRequest(
                endpoint = endpoint,
                isolationKey = isolation,
                clientAddr = clientAddr,
                optimisticData = optimisticData,
                via = ProxyKind.Socks5,
            ),
        )
        Socks5Command.Bind -> Socks5Outcome.Bind(endpoint, isolation, clientAddr)
        Socks5Command.UdpAssociate -> Socks5Outcome.UdpAssociate(endpoint, isolation, clientAddr)
        null -> {
            local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.CommandNotSupported)))
            null
        }
    }
}

/** CONNECT-only helper for bilingual frontends. */
suspend fun negotiateSocks5Connect(
    local: BufferedBytePipe,
    preferUserPass: Boolean = true,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): TorRouteRequest? = when (
    val o = negotiateSocks5(local, preferUserPass, optimisticData, clientAddr)
) {
    is Socks5Outcome.Connect -> o.route
    is Socks5Outcome.Bind -> {
        local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.CommandNotSupported)))
        null
    }
    is Socks5Outcome.UdpAssociate -> {
        local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.CommandNotSupported)))
        null
    }
    null -> null
}

suspend fun writeSocks5Success(local: BytePipe) {
    local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(Socks5Reply.Succeeded)))
}

suspend fun writeSocks5Failure(local: BytePipe, reply: Socks5Reply) {
    local.write(Socks5Codec.encodeReply(Socks5Codec.Reply(reply)))
}

/** SOCKS4 / SOCKS4a CONNECT. */
suspend fun negotiateSocks4(
    local: BufferedBytePipe,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): TorRouteRequest? {
    val ver = local.readByte()
    if (ver != Socks4Codec.VERSION) return null
    val cmd = local.readByte()
    val port = (local.readByte() shl 8) or local.readByte()
    val ip = local.readFully(4)
    val userBytes = ArrayList<Byte>()
    while (true) {
        val b = local.readByte()
        if (b < 0) return null
        if (b == 0) break
        userBytes.add(b.toByte())
    }
    val userId = userBytes.toByteArray().toString(Charsets.ISO_8859_1)
    val is4a = ip[0] == 0.toByte() && ip[1] == 0.toByte() && ip[2] == 0.toByte() && ip[3] != 0.toByte()
    val endpoint = if (is4a) {
        val domain = ArrayList<Byte>()
        while (true) {
            val b = local.readByte()
            if (b < 0) return null
            if (b == 0) break
            domain.add(b.toByte())
        }
        NetEndpoint.Domain(domain.toByteArray().toString(Charsets.ISO_8859_1), port)
    } else {
        NetEndpoint.Ipv4(ip, port)
    }
    if (cmd != Socks4Codec.CMD_CONNECT) {
        local.write(Socks4Codec.encodeReply(Socks4Codec.REP_REJECTED))
        return null
    }
    return TorRouteRequest(
        endpoint = endpoint,
        isolationKey = userId.ifEmpty { null },
        clientAddr = clientAddr,
        optimisticData = optimisticData,
        via = ProxyKind.Socks4,
    )
}

suspend fun writeSocks4Success(local: BytePipe) {
    local.write(Socks4Codec.encodeReply(Socks4Codec.REP_GRANTED))
}

/** HTTP CONNECT / OPTIONS / absolute-form (RFC 9110 + prop365). */
sealed class HttpProxyOutcome {
    data class Tunnel(val route: TorRouteRequest) : HttpProxyOutcome()
    data class AbsoluteForward(
        val route: TorRouteRequest,
        val originRequest: ByteArray,
    ) : HttpProxyOutcome()
    /** OPTIONS answered; caller should close. */
    data object OptionsDone : HttpProxyOutcome()
}

suspend fun negotiateHttpProxy(
    local: BufferedBytePipe,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): HttpProxyOutcome? {
    val head = local.readHttpHead()
    return when (val msg = HttpProxyCodec.parse(head)) {
        is HttpProxyCodec.Message.Connect -> HttpProxyOutcome.Tunnel(
            TorRouteRequest(
                endpoint = msg.request.endpoint,
                isolationKey = msg.request.isolationKey,
                clientAddr = clientAddr,
                familyPreference = msg.request.familyPreference,
                optimisticData = optimisticData,
                via = ProxyKind.HttpConnect,
            ),
        )
        is HttpProxyCodec.Message.Options -> {
            local.write(HttpProxyCodec.optionsResponse())
            HttpProxyOutcome.OptionsDone
        }
        is HttpProxyCodec.Message.Absolute -> {
            // Optional body already buffered after headers? readHttpHead stops at CRLFCRLF.
            val origin = HttpProxyCodec.toOriginForm(msg)
            HttpProxyOutcome.AbsoluteForward(
                route = TorRouteRequest(
                    endpoint = msg.endpoint,
                    isolationKey = msg.isolationKey,
                    clientAddr = clientAddr,
                    familyPreference = msg.familyPreference,
                    optimisticData = optimisticData,
                    via = ProxyKind.HttpAbsolute,
                ),
                originRequest = origin,
            )
        }
        null -> {
            local.write(HttpConnectCodec.encodeResponse(405, "Method Not Allowed", HttpProxyCodec.torResponseHeaders()))
            null
        }
    }
}

/** HTTP CONNECT-only (back-compat). */
suspend fun negotiateHttpConnect(
    local: BufferedBytePipe,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): TorRouteRequest? = when (
    val o = negotiateHttpProxy(local, optimisticData, clientAddr)
) {
    is HttpProxyOutcome.Tunnel -> o.route
    is HttpProxyOutcome.AbsoluteForward -> o.route
    is HttpProxyOutcome.OptionsDone -> null
    null -> null
}

suspend fun writeHttpConnectSuccess(local: BytePipe) {
    local.write(HttpProxyCodec.connectionEstablished())
}

/**
 * Peek TLS ClientHello (RFC 8446) for SNI, push bytes back for transparent splice.
 */
suspend fun negotiateTlsSni(
    local: BufferedBytePipe,
    defaultPort: Int = 443,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): TorRouteRequest? {
    val first = ByteArray(5)
    var got = 0
    while (got < 5) {
        val n = local.read(first, got, 5 - got)
        if (n < 0) return null
        got += n
    }
    val recLen = ((first[3].toInt() and 0xff) shl 8) or (first[4].toInt() and 0xff)
    val rest = local.readFully(recLen)
    val record = first + rest
    val peek = TlsClientHello.parse(record) ?: run {
        local.pushFront(record)
        return null
    }
    local.pushFront(record)
    val host = peek.serverName ?: return null
    return TorRouteRequest(
        endpoint = NetEndpoint.Domain(host, defaultPort),
        clientAddr = clientAddr,
        optimisticData = optimisticData,
        via = ProxyKind.TlsSni,
    )
}

/** Bilingual / multilingual local frontend outcome. */
sealed class LocalProxyOutcome {
    data class Route(val route: TorRouteRequest, val prelude: ByteArray = ByteArray(0)) : LocalProxyOutcome()
    data object Done : LocalProxyOutcome()
}

/**
 * Prop365+ : SOCKS4/5, HTTP CONNECT/OPTIONS/absolute-form, TLS SNI peek.
 */
suspend fun negotiateMultilingual(
    local: BufferedBytePipe,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): LocalProxyOutcome? {
    val first = local.readByte()
    if (first < 0) return null
    local.pushFront(byteArrayOf(first.toByte()))
    return when (ProtocolDetector.detect(first)) {
        LocalProtocol.Socks5 -> {
            val r = negotiateSocks5Connect(local, optimisticData = optimisticData, clientAddr = clientAddr)
                ?: return null
            LocalProxyOutcome.Route(r)
        }
        LocalProtocol.Socks4 -> {
            val r = negotiateSocks4(local, optimisticData = optimisticData, clientAddr = clientAddr)
                ?: return null
            LocalProxyOutcome.Route(r)
        }
        LocalProtocol.Http -> when (val h = negotiateHttpProxy(local, optimisticData, clientAddr)) {
            is HttpProxyOutcome.Tunnel -> LocalProxyOutcome.Route(h.route)
            is HttpProxyOutcome.AbsoluteForward -> LocalProxyOutcome.Route(h.route, h.originRequest)
            is HttpProxyOutcome.OptionsDone -> LocalProxyOutcome.Done
            null -> null
        }
        LocalProtocol.Tls -> {
            val r = negotiateTlsSni(local, optimisticData = optimisticData, clientAddr = clientAddr)
                ?: return null
            LocalProxyOutcome.Route(r)
        }
        LocalProtocol.Unknown -> null
    }
}

/**
 * Prop365 bilingual: peek first byte, dispatch SOCKS4/5 or HTTP CONNECT.
 */
suspend fun negotiateBilingual(
    local: BufferedBytePipe,
    optimisticData: Boolean = true,
    clientAddr: String? = null,
): TorRouteRequest? = when (
    val o = negotiateMultilingual(local, optimisticData, clientAddr)
) {
    is LocalProxyOutcome.Route -> if (o.prelude.isEmpty()) o.route else o.route
    is LocalProxyOutcome.Done -> null
    null -> null
}

