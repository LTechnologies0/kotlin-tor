package org.kotlintor.net

/**
 * SOCKS4/5 proto helpers (C Tor `proto_socks.c`).
 *
 * Inventory: `L1:core/proto/proto_socks.c`
 *
 * Implementation: [Socks5Codec], [Socks4Codec].
 */
object ProtoSocks {
    const val VERSION5: Int = 5
    const val VERSION4: Int = 4

    fun parseMethodOffer(buf: ByteArray) = Socks5Codec.parseMethodOffer(buf)

    fun parseRequest(buf: ByteArray) = Socks5Codec.parseRequest(buf)

    fun parseSocks4Request(buf: ByteArray) = Socks4Codec.parseRequest(buf)

    fun encodeMethodSelect(method: Int): ByteArray =
        Socks5Codec.encodeMethodSelect(method)

    fun encodeReply(reply: Socks5Reply, bind: NetEndpoint = NetEndpoint.Ipv4(byteArrayOf(0, 0, 0, 0), 0)): ByteArray =
        Socks5Codec.encodeReply(Socks5Codec.Reply(reply, bind))

    fun isSocks5Greeting(buf: ByteArray): Boolean =
        buf.isNotEmpty() && (buf[0].toInt() and 0xff) == VERSION5

    fun isSocks4Greeting(buf: ByteArray): Boolean =
        buf.isNotEmpty() && (buf[0].toInt() and 0xff) == VERSION4
}
