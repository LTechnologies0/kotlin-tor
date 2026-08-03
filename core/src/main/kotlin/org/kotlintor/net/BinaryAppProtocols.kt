package org.kotlintor.net

import java.nio.charset.StandardCharsets

/**
 * MQTT v3.1.1 fixed header + Remaining Length (OASIS MQTT / MQTT-v3.1.1).
 * Control packet type in bits 7–4 of byte 1; CONNECT = 1 → 0x10.
 */
object MqttCodec {
    enum class PacketType(val code: Int) {
        Reserved0(0),
        Connect(1),
        Connack(2),
        Publish(3),
        Puback(4),
        Pubrec(5),
        Pubrel(6),
        Pubcomp(7),
        Subscribe(8),
        Suback(9),
        Unsubscribe(10),
        Unsuback(11),
        Pingreq(12),
        Pingresp(13),
        Disconnect(14),
        Reserved15(15),
        ;

        companion object {
            fun from(code: Int): PacketType? = entries.firstOrNull { it.code == code }
        }
    }

    data class FixedHeader(val type: PacketType, val flags: Int, val remainingLength: Int)

    /** Encode Remaining Length per MQTT §2.2.3 (1–4 bytes). */
    fun encodeRemainingLength(value: Int): ByteArray {
        require(value in 0..268_435_455)
        val out = ArrayList<Byte>(4)
        var x = value
        do {
            var enc = x % 128
            x /= 128
            if (x > 0) enc = enc or 0x80
            out += enc.toByte()
        } while (x > 0)
        return out.toByteArray()
    }

    /** @return pair(length, bytesConsumed) or null if incomplete/invalid. */
    fun decodeRemainingLength(buf: ByteArray, offset: Int = 0): Pair<Int, Int>? {
        var multiplier = 1
        var value = 0
        var i = offset
        var encodedByte: Int
        do {
            if (i >= buf.size) return null
            if (i - offset >= 4) return null
            encodedByte = buf[i].toInt() and 0xff
            i++
            value += (encodedByte and 0x7f) * multiplier
            multiplier *= 128
        } while ((encodedByte and 0x80) != 0)
        return value to (i - offset)
    }

    fun parseFixedHeader(buf: ByteArray, offset: Int = 0): FixedHeader? {
        if (buf.size - offset < 2) return null
        val b1 = buf[offset].toInt() and 0xff
        val type = PacketType.from(b1 ushr 4) ?: return null
        val flags = b1 and 0x0f
        val (rl, n) = decodeRemainingLength(buf, offset + 1) ?: return null
        return FixedHeader(type, flags, rl)
    }

    fun encodeFixedHeader(type: PacketType, flags: Int, remainingLength: Int): ByteArray {
        val b1 = ((type.code shl 4) or (flags and 0x0f)).toByte()
        return byteArrayOf(b1) + encodeRemainingLength(remainingLength)
    }

    /** True if buffer looks like MQTT CONNECT (type=1, protocol name often follows). */
    fun looksLikeConnect(first: ByteArray): Boolean {
        val h = parseFixedHeader(first) ?: return false
        return h.type == PacketType.Connect && h.flags == 0
    }
}

/**
 * LDAP BER framing (RFC 4511 §5): LDAPMessage is a BER SEQUENCE (tag 0x30).
 * We only frame messages — no full ASN.1 decode.
 */
object LdapBer {
    data class Frame(val tag: Int, val content: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is Frame && tag == other.tag && content.contentEquals(other.content)

        override fun hashCode(): Int = 31 * tag + content.contentHashCode()
    }

    fun encodeLength(len: Int): ByteArray {
        require(len >= 0)
        return when {
            len < 0x80 -> byteArrayOf(len.toByte())
            len <= 0xff -> byteArrayOf(0x81.toByte(), len.toByte())
            len <= 0xffff -> byteArrayOf(
                0x82.toByte(),
                ((len ushr 8) and 0xff).toByte(),
                (len and 0xff).toByte(),
            )
            else -> byteArrayOf(
                0x83.toByte(),
                ((len ushr 16) and 0xff).toByte(),
                ((len ushr 8) and 0xff).toByte(),
                (len and 0xff).toByte(),
            )
        }
    }

    /** @return Pair(length, headerBytes) or null if incomplete. */
    fun decodeLength(buf: ByteArray, offset: Int): Pair<Int, Int>? {
        if (offset >= buf.size) return null
        val b0 = buf[offset].toInt() and 0xff
        if (b0 < 0x80) return b0 to 1
        val n = b0 and 0x7f
        if (n == 0 || n > 4) return null
        if (buf.size - offset < 1 + n) return null
        var len = 0
        for (i in 1..n) {
            len = (len shl 8) or (buf[offset + i].toInt() and 0xff)
        }
        return len to (1 + n)
    }

    fun wrapSequence(content: ByteArray): ByteArray =
        byteArrayOf(0x30) + encodeLength(content.size) + content

    /** Parse one top-level TLV; returns null if incomplete. */
    fun parseFrame(buf: ByteArray, offset: Int = 0): Pair<Frame, Int>? {
        if (buf.size - offset < 2) return null
        val tag = buf[offset].toInt() and 0xff
        val (len, ln) = decodeLength(buf, offset + 1) ?: return null
        val contentStart = offset + 1 + ln
        if (buf.size - contentStart < len) return null
        val content = buf.copyOfRange(contentStart, contentStart + len)
        return Frame(tag, content) to (1 + ln + len)
    }

    fun looksLikeLdap(first: ByteArray): Boolean =
        first.isNotEmpty() && (first[0].toInt() and 0xff) == 0x30
}

/**
 * XMPP stream open (RFC 6120 §4.2): client sends an XML stream header over TCP.
 */
object XmppStream {
    data class Open(
        val to: String?,
        val from: String?,
        val version: String?,
        val lang: String?,
    )

    private val ATTR = Regex("""(\w+)=["']([^"']*)["']""")

    fun parseOpen(xml: String): Open? {
        val t = xml.trim()
        if (!t.contains("<stream:stream", ignoreCase = true) &&
            !t.contains("<stream:stream")
        ) {
            // also accept default-ns stream
            if (!t.startsWith("<?xml", true) && !t.contains("stream:stream")) return null
        }
        if (!t.contains("stream:stream")) return null
        val attrs = ATTR.findAll(t).associate { it.groupValues[1] to it.groupValues[2] }
        return Open(
            to = attrs["to"],
            from = attrs["from"],
            version = attrs["version"],
            lang = attrs["xml:lang"] ?: attrs["lang"],
        )
    }

    fun encodeOpen(to: String, from: String? = null, version: String = "1.0"): ByteArray {
        val sb = StringBuilder()
        sb.append("<?xml version='1.0'?>")
        sb.append("<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'")
        sb.append(" to='").append(to).append("'")
        if (from != null) sb.append(" from='").append(from).append("'")
        sb.append(" version='").append(version).append("'")
        sb.append('>')
        return sb.toString().toByteArray(StandardCharsets.UTF_8)
    }

    fun looksLike(first: ByteArray): Boolean {
        val s = first.toString(Charsets.US_ASCII)
        return s.contains("stream:stream", ignoreCase = true) ||
            (s.trimStart().startsWith("<?xml", ignoreCase = true) && s.contains("jabber", true))
    }
}

/**
 * PostgreSQL Frontend/Backend StartupMessage (protocol 3.0).
 * Length-prefixed; version 196608 (3.0) or 196610 (3.2).
 */
object PostgresStartup {
    const val PROTOCOL_3_0: Int = 196608
    const val PROTOCOL_3_2: Int = 196610

    data class Message(val protocol: Int, val params: Map<String, String>)

    fun encode(user: String, database: String? = null, protocol: Int = PROTOCOL_3_0): ByteArray {
        val params = LinkedHashMap<String, String>()
        params["user"] = user
        if (database != null) params["database"] = database
        val body = ArrayList<Byte>()
        fun putInt32(v: Int) {
            body += ((v ushr 24) and 0xff).toByte()
            body += ((v ushr 16) and 0xff).toByte()
            body += ((v ushr 8) and 0xff).toByte()
            body += (v and 0xff).toByte()
        }
        fun putCString(s: String) {
            for (b in s.toByteArray(Charsets.UTF_8)) body.add(b)
            body.add(0)
        }
        // placeholder length
        putInt32(0)
        putInt32(protocol)
        for ((k, v) in params) {
            putCString(k)
            putCString(v)
        }
        body += 0 // terminator
        val arr = body.toByteArray()
        val len = arr.size
        arr[0] = ((len ushr 24) and 0xff).toByte()
        arr[1] = ((len ushr 16) and 0xff).toByte()
        arr[2] = ((len ushr 8) and 0xff).toByte()
        arr[3] = (len and 0xff).toByte()
        return arr
    }

    fun parse(buf: ByteArray, offset: Int = 0): Pair<Message, Int>? {
        if (buf.size - offset < 8) return null
        val len = ((buf[offset].toInt() and 0xff) shl 24) or
            ((buf[offset + 1].toInt() and 0xff) shl 16) or
            ((buf[offset + 2].toInt() and 0xff) shl 8) or
            (buf[offset + 3].toInt() and 0xff)
        if (buf.size - offset < len) return null
        val proto = ((buf[offset + 4].toInt() and 0xff) shl 24) or
            ((buf[offset + 5].toInt() and 0xff) shl 16) or
            ((buf[offset + 6].toInt() and 0xff) shl 8) or
            (buf[offset + 7].toInt() and 0xff)
        var o = offset + 8
        val end = offset + len
        val params = LinkedHashMap<String, String>()
        while (o < end) {
            if (buf[o].toInt() == 0) {
                o++
                break
            }
            val keyEnd = (o until end).firstOrNull { buf[it].toInt() == 0 } ?: return null
            val key = buf.copyOfRange(o, keyEnd).toString(Charsets.UTF_8)
            o = keyEnd + 1
            val valEnd = (o until end).firstOrNull { buf[it].toInt() == 0 } ?: return null
            val value = buf.copyOfRange(o, valEnd).toString(Charsets.UTF_8)
            o = valEnd + 1
            params[key] = value
        }
        return Message(proto, params) to len
    }

    fun looksLike(first: ByteArray): Boolean {
        if (first.size < 8) return false
        val len = ((first[0].toInt() and 0xff) shl 24) or
            ((first[1].toInt() and 0xff) shl 16) or
            ((first[2].toInt() and 0xff) shl 8) or
            (first[3].toInt() and 0xff)
        if (len < 8 || len > 10_000) return false
        val proto = ((first[4].toInt() and 0xff) shl 24) or
            ((first[5].toInt() and 0xff) shl 16) or
            ((first[6].toInt() and 0xff) shl 8) or
            (first[7].toInt() and 0xff)
        return proto == PROTOCOL_3_0 || proto == PROTOCOL_3_2
    }
}
