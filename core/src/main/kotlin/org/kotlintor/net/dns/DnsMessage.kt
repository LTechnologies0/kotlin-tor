package org.kotlintor.net.dns

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.random.Random

class DnsException(message: String) : Exception(message)

data class DnsQuestion(
    val name: String,
    val type: Int,
    val klass: Int = DnsTypes.CLASS_IN,
)

data class DnsRr(
    val name: String,
    val type: Int,
    val klass: Int,
    val ttl: Long,
    val rdata: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is DnsRr && name == other.name && type == other.type &&
            klass == other.klass && rdata.contentEquals(other.rdata)

    override fun hashCode(): Int =
        ((name.hashCode() * 31 + type) * 31 + klass) * 31 + rdata.contentHashCode()
}

data class DnsPacket(
    val id: Int,
    val flags: Int,
    val questions: List<DnsQuestion>,
    val answers: List<DnsRr>,
    val authorities: List<DnsRr>,
    val additionals: List<DnsRr>,
) {
    val qr: Boolean get() = flags and 0x8000 != 0
    val aa: Boolean get() = flags and 0x0400 != 0
    val tc: Boolean get() = flags and 0x0200 != 0
    val rd: Boolean get() = flags and 0x0100 != 0
    val ra: Boolean get() = flags and 0x0080 != 0
    val ad: Boolean get() = flags and 0x0020 != 0
    val cd: Boolean get() = flags and 0x0010 != 0
    val rcode: Int get() = flags and 0x000f
    val opcode: Int get() = (flags ushr 11) and 0x0f

    fun allRecords(): List<DnsRr> = answers + authorities + additionals.filter { it.type != DnsTypes.OPT }
}

object DnsMessage {
    fun canonicalizeName(name: String): String {
        var n = name.trim().lowercase()
        while (n.endsWith(".")) n = n.dropLast(1)
        return n
    }

    fun buildQuery(
        qname: String,
        qtype: Int,
        id: Int = Random.nextInt(0, 65536),
        recursionDesired: Boolean = true,
        dnssecOk: Boolean = true,
        ednsUdpPayload: Int = 1232,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, id and 0xffff)
        var flags = if (recursionDesired) 0x0100 else 0
        writeU16(out, flags)
        writeU16(out, 1) // QD
        writeU16(out, 0)
        writeU16(out, 0)
        writeU16(out, if (dnssecOk) 1 else 0) // AR = OPT
        writeName(out, qname)
        writeU16(out, qtype)
        writeU16(out, DnsTypes.CLASS_IN)
        if (dnssecOk) {
            // OPT RR: root name, type 41, class = UDP size, TTL: ext-rcode|version|Z(DO)
            out.write(0)
            writeU16(out, DnsTypes.OPT)
            writeU16(out, ednsUdpPayload and 0xffff)
            // TTL: DO bit is bit 15 of the upper 16 of Z in OPT (RFC 6891) — stored in flags field of OPT as 0x8000 in the 16-bit Z
            writeU16(out, 0) // ext RCODE + version
            writeU16(out, 0x8000) // DO=1
            writeU16(out, 0) // rdlen
        }
        return out.toByteArray()
    }

    fun parse(message: ByteArray): DnsPacket {
        if (message.size < 12) throw DnsException("DNS message too short")
        val buf = ByteBuffer.wrap(message).order(ByteOrder.BIG_ENDIAN)
        val id = buf.short.toInt() and 0xffff
        val flags = buf.short.toInt() and 0xffff
        val qd = buf.short.toInt() and 0xffff
        val an = buf.short.toInt() and 0xffff
        val ns = buf.short.toInt() and 0xffff
        val ar = buf.short.toInt() and 0xffff
        val questions = ArrayList<DnsQuestion>(qd)
        repeat(qd) {
            val name = readName(buf, message)
            val type = buf.short.toInt() and 0xffff
            val klass = buf.short.toInt() and 0xffff
            questions += DnsQuestion(name, type, klass)
        }
        fun readSection(n: Int): List<DnsRr> {
            val list = ArrayList<DnsRr>(n)
            repeat(n) {
                val name = readName(buf, message)
                val type = buf.short.toInt() and 0xffff
                val klass = buf.short.toInt() and 0xffff
                val ttl = buf.int.toLong() and 0xffff_ffffL
                val rdlen = buf.short.toInt() and 0xffff
                if (buf.remaining() < rdlen) throw DnsException("Truncated rdata")
                val rdata = ByteArray(rdlen)
                buf.get(rdata)
                list += DnsRr(name, type, klass, ttl, rdata)
            }
            return list
        }
        return DnsPacket(
            id = id,
            flags = flags,
            questions = questions,
            answers = readSection(an),
            authorities = readSection(ns),
            additionals = readSection(ar),
        )
    }

    fun writeName(out: ByteArrayOutputStream, name: String) {
        val n = canonicalizeName(name)
        if (n.isEmpty()) {
            out.write(0)
            return
        }
        for (label in n.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "bad label length" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
    }

    fun readName(buf: ByteBuffer, message: ByteArray, depth: Int = 0): String {
        if (depth > 20) throw DnsException("Compression loop")
        val labels = ArrayList<String>()
        while (true) {
            if (!buf.hasRemaining()) throw DnsException("Truncated name")
            val len = buf.get().toInt() and 0xff
            when {
                len == 0 -> break
                (len and 0xc0) == 0xc0 -> {
                    if (!buf.hasRemaining()) throw DnsException("Truncated pointer")
                    val b2 = buf.get().toInt() and 0xff
                    val ptr = ((len and 0x3f) shl 8) or b2
                    if (ptr >= message.size) throw DnsException("Bad compression pointer")
                    val nested = ByteBuffer.wrap(message).order(ByteOrder.BIG_ENDIAN)
                    nested.position(ptr)
                    val rest = readName(nested, message, depth + 1)
                    if (rest.isNotEmpty()) labels += rest.split('.')
                    return labels.joinToString(".")
                }
                else -> {
                    if (buf.remaining() < len) throw DnsException("Truncated label")
                    val bytes = ByteArray(len)
                    buf.get(bytes)
                    labels += bytes.toString(Charsets.US_ASCII).lowercase()
                }
            }
        }
        return labels.joinToString(".")
    }

    /** Uncompressed wire name ending with 0 (for RRSIG signer field etc.). */
    fun encodeNameUncompressed(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        writeName(out, name)
        return out.toByteArray()
    }

    fun aRdata(ipv4: String): ByteArray {
        val p = ipv4.split('.')
        require(p.size == 4)
        return ByteArray(4) { i -> p[i].toInt().toByte() }
    }

    fun aaaaRdata(ipv6: String): ByteArray =
        java.net.InetAddress.getByName(ipv6).address.also { require(it.size == 16) }

    fun parseA(rdata: ByteArray): String {
        require(rdata.size == 4)
        return rdata.joinToString(".") { (it.toInt() and 0xff).toString() }
    }

    fun parseAaaa(rdata: ByteArray): String {
        require(rdata.size == 16)
        return java.net.InetAddress.getByAddress(rdata).hostAddress
    }

    fun writeU16(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 8) and 0xff)
        out.write(v and 0xff)
    }

    fun writeU32(out: ByteArrayOutputStream, v: Long) {
        out.write(((v ushr 24) and 0xff).toInt())
        out.write(((v ushr 16) and 0xff).toInt())
        out.write(((v ushr 8) and 0xff).toInt())
        out.write((v and 0xff).toInt())
    }
}
