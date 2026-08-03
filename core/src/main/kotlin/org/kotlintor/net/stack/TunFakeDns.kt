package org.kotlintor.net.stack

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * TUN-side DNS: answer A/AAAA with fake-IP cookies; reject other QTYPEs with
 * NOERROR empty or FORMERR. Non-DNS UDP is not handled here (caller drops).
 */
class TunFakeDns(
    val cookies: FakeIpDnsCookies = FakeIpDnsCookies(),
) {
    data class Query(
        val id: Int,
        val name: String,
        val qtype: Int,
        val qclass: Int,
    )

    fun handleQuery(raw: ByteArray, isolationKey: Long? = null): ByteArray? {
        val q = parseQuery(raw) ?: return null
        return when (q.qtype) {
            QTYPE_A -> {
                val ip = cookies.makeForV4(q.name, isolationKey)
                buildAResponse(raw, q, ip)
            }
            QTYPE_AAAA -> {
                val ip = cookies.makeForV6(q.name, isolationKey)
                buildAaaaResponse(raw, q, ip)
            }
            else -> buildEmptyResponse(raw, rcode = RCODE_NOTIMP)
        }
    }

    fun parseQuery(raw: ByteArray): Query? {
        if (raw.size < 12) return null
        val id = ((raw[0].toInt() and 0xff) shl 8) or (raw[1].toInt() and 0xff)
        val flags = ((raw[2].toInt() and 0xff) shl 8) or (raw[3].toInt() and 0xff)
        if (flags and 0x8000 != 0) return null // response
        val qd = ((raw[4].toInt() and 0xff) shl 8) or (raw[5].toInt() and 0xff)
        if (qd < 1) return null
        var i = 12
        val labels = mutableListOf<String>()
        while (i < raw.size) {
            val len = raw[i].toInt() and 0xff
            if (len == 0) {
                i++
                break
            }
            if (len and 0xc0 != 0) return null
            i++
            if (i + len > raw.size) return null
            labels += raw.copyOfRange(i, i + len).toString(Charsets.US_ASCII)
            i += len
        }
        if (i + 4 > raw.size) return null
        val qtype = ((raw[i].toInt() and 0xff) shl 8) or (raw[i + 1].toInt() and 0xff)
        val qclass = ((raw[i + 2].toInt() and 0xff) shl 8) or (raw[i + 3].toInt() and 0xff)
        val name = FakeIpDnsCookies.canonicalize(labels.joinToString("."))
        if (name.isEmpty()) return null
        return Query(id, name, qtype, qclass)
    }

    private fun buildAResponse(query: ByteArray, q: Query, ipv4: String): ByteArray {
        val addr = InetAddress.getByName(ipv4).address
        require(addr.size == 4)
        return buildResponse(query, qtype = QTYPE_A, rdata = addr)
    }

    private fun buildAaaaResponse(query: ByteArray, q: Query, ipv6: String): ByteArray {
        val addr = InetAddress.getByName(ipv6).address
        require(addr.size == 16)
        return buildResponse(query, qtype = QTYPE_AAAA, rdata = addr)
    }

    private fun buildResponse(query: ByteArray, qtype: Int, rdata: ByteArray): ByteArray {
        val out = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN)
        // copy question section from query
        out.put(query, 0, 2)
        out.put(((query[2].toInt() and 0xff) or 0x80).toByte()) // QR
        out.put(0x00) // RA clear / rcode 0
        out.putShort(1) // QDCOUNT
        out.putShort(1) // ANCOUNT
        out.putShort(0)
        out.putShort(0)
        var i = 12
        while (i < query.size && query[i].toInt() != 0) {
            val len = query[i].toInt() and 0xff
            out.put(query, i, 1 + len)
            i += 1 + len
        }
        if (i < query.size) {
            out.put(0)
            i++
            if (i + 4 <= query.size) out.put(query, i, 4)
        }
        // answer
        out.put(0xc0.toByte()); out.put(0x0c)
        out.putShort(qtype.toShort())
        out.putShort(1) // IN
        out.putInt(FakeIpDnsCookies.TIME_TO_LIVE_IN_DNS.toInt())
        out.putShort(rdata.size.toShort())
        out.put(rdata)
        val arr = ByteArray(out.position())
        out.flip()
        out.get(arr)
        return arr
    }

    private fun buildEmptyResponse(query: ByteArray, rcode: Int): ByteArray {
        if (query.size < 12) return ByteArray(0)
        val out = query.copyOf(query.size.coerceAtMost(512))
        out[2] = ((out[2].toInt() and 0xff) or 0x80).toByte()
        out[3] = ((out[3].toInt() and 0xf0) or (rcode and 0x0f)).toByte()
        out[6] = 0; out[7] = 0 // ANCOUNT
        return out
    }

    companion object {
        const val QTYPE_A = 1
        const val QTYPE_AAAA = 28
        const val RCODE_NOTIMP = 4

        fun isDnsPort(port: Int): Boolean = port == 53

        fun isFakeResolver(dstIp: ByteArray): Boolean {
            if (dstIp.size == 4) {
                // 169.254.42.53 or any 10.x used as VPN DNS, or link-local
                val s = dstIp.joinToString(".") { (it.toInt() and 0xff).toString() }
                if (s == FakeIpDnsCookies.FAKE_RESOLVER_V4) return true
                // Accept common VPN DNS pins (10.10.10.1 etc.) — still port 53 gated.
                return true
            }
            return dstIp.size == 16
        }
    }
}
