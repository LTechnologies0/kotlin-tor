package org.kotlintor.net.dns

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

data class DnskeyRdata(
    val flags: Int,
    val protocol: Int,
    val algorithm: Int,
    val publicKey: ByteArray,
) {
    val isZoneKey: Boolean get() = flags and 0x0100 != 0
    val isSecureEntryPoint: Boolean get() = flags and 0x0001 != 0

    fun toBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        DnsMessage.writeU16(out, flags)
        out.write(protocol and 0xff)
        out.write(algorithm and 0xff)
        out.write(publicKey)
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is DnskeyRdata && flags == other.flags && protocol == other.protocol &&
            algorithm == other.algorithm && publicKey.contentEquals(other.publicKey)

    override fun hashCode(): Int =
        ((flags * 31 + protocol) * 31 + algorithm) * 31 + publicKey.contentHashCode()

    companion object {
        fun parse(rdata: ByteArray): DnskeyRdata {
            if (rdata.size < 4) throw DnsException("DNSKEY rdata too short")
            val buf = ByteBuffer.wrap(rdata).order(ByteOrder.BIG_ENDIAN)
            val flags = buf.short.toInt() and 0xffff
            val proto = buf.get().toInt() and 0xff
            val alg = buf.get().toInt() and 0xff
            val key = ByteArray(buf.remaining())
            buf.get(key)
            return DnskeyRdata(flags, proto, alg, key)
        }
    }
}

data class DsRdata(
    val keyTag: Int,
    val algorithm: Int,
    val digestType: Int,
    val digest: ByteArray,
) {
    fun toBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        DnsMessage.writeU16(out, keyTag)
        out.write(algorithm and 0xff)
        out.write(digestType and 0xff)
        out.write(digest)
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is DsRdata && keyTag == other.keyTag && algorithm == other.algorithm &&
            digestType == other.digestType && digest.contentEquals(other.digest)

    override fun hashCode(): Int =
        ((keyTag * 31 + algorithm) * 31 + digestType) * 31 + digest.contentHashCode()

    companion object {
        const val DIGEST_SHA1 = 1
        const val DIGEST_SHA256 = 2

        fun parse(rdata: ByteArray): DsRdata {
            if (rdata.size < 4) throw DnsException("DS rdata too short")
            val buf = ByteBuffer.wrap(rdata).order(ByteOrder.BIG_ENDIAN)
            val tag = buf.short.toInt() and 0xffff
            val alg = buf.get().toInt() and 0xff
            val dt = buf.get().toInt() and 0xff
            val dig = ByteArray(buf.remaining())
            buf.get(dig)
            return DsRdata(tag, alg, dt, dig)
        }
    }
}

data class RrsigRdata(
    val typeCovered: Int,
    val algorithm: Int,
    val labels: Int,
    val originalTtl: Long,
    val expiration: Long,
    val inception: Long,
    val keyTag: Int,
    val signerName: String,
    val signature: ByteArray,
) {
    companion object {
        fun parse(rdata: ByteArray): RrsigRdata {
            if (rdata.size < 18) throw DnsException("RRSIG rdata too short")
            val buf = ByteBuffer.wrap(rdata).order(ByteOrder.BIG_ENDIAN)
            val typeCovered = buf.short.toInt() and 0xffff
            val alg = buf.get().toInt() and 0xff
            val labels = buf.get().toInt() and 0xff
            val origTtl = buf.int.toLong() and 0xffff_ffffL
            val exp = buf.int.toLong() and 0xffff_ffffL
            val inc = buf.int.toLong() and 0xffff_ffffL
            val tag = buf.short.toInt() and 0xffff
            val rest = ByteArray(buf.remaining())
            buf.get(rest)
            val nameBuf = ByteBuffer.wrap(rest).order(ByteOrder.BIG_ENDIAN)
            val signer = DnsMessage.readName(nameBuf, rest)
            val sigOff = nameBuf.position()
            val sig = rest.copyOfRange(sigOff, rest.size)
            return RrsigRdata(typeCovered, alg, labels, origTtl, exp, inc, tag, signer, sig)
        }
    }
}

data class NsecRdata(
    val nextDomain: String,
    val typeBitMaps: ByteArray,
) {
    fun types(): Set<Int> = TypeBitMaps.decode(typeBitMaps)

    companion object {
        fun parse(rdata: ByteArray): NsecRdata {
            val buf = ByteBuffer.wrap(rdata).order(ByteOrder.BIG_ENDIAN)
            val next = DnsMessage.readName(buf, rdata)
            val maps = ByteArray(buf.remaining())
            buf.get(maps)
            return NsecRdata(next, maps)
        }
    }
}

data class Nsec3Rdata(
    val hashAlg: Int,
    val flags: Int,
    val iterations: Int,
    val salt: ByteArray,
    val nextHashed: ByteArray,
    val typeBitMaps: ByteArray,
) {
    fun types(): Set<Int> = TypeBitMaps.decode(typeBitMaps)

    companion object {
        fun parse(rdata: ByteArray): Nsec3Rdata {
            if (rdata.size < 5) throw DnsException("NSEC3 rdata too short")
            val buf = ByteBuffer.wrap(rdata).order(ByteOrder.BIG_ENDIAN)
            val hashAlg = buf.get().toInt() and 0xff
            val flags = buf.get().toInt() and 0xff
            val iterations = buf.short.toInt() and 0xffff
            val saltLen = buf.get().toInt() and 0xff
            if (buf.remaining() < saltLen + 1) throw DnsException("NSEC3 salt truncated")
            val salt = ByteArray(saltLen)
            buf.get(salt)
            val hashLen = buf.get().toInt() and 0xff
            if (buf.remaining() < hashLen) throw DnsException("NSEC3 hash truncated")
            val next = ByteArray(hashLen)
            buf.get(next)
            val maps = ByteArray(buf.remaining())
            buf.get(maps)
            return Nsec3Rdata(hashAlg, flags, iterations, salt, next, maps)
        }
    }
}

object TypeBitMaps {
    fun decode(maps: ByteArray): Set<Int> {
        val out = HashSet<Int>()
        var i = 0
        while (i + 2 <= maps.size) {
            val window = maps[i].toInt() and 0xff
            val len = maps[i + 1].toInt() and 0xff
            i += 2
            if (i + len > maps.size) break
            for (j in 0 until len) {
                val b = maps[i + j].toInt() and 0xff
                for (bit in 0 until 8) {
                    if ((b and (0x80 ushr bit)) != 0) {
                        out += window * 256 + j * 8 + bit
                    }
                }
            }
            i += len
        }
        return out
    }
}

object DnssecCrypto {
    /** RFC 4034 appendix B key tag. */
    fun keyTag(dnskeyRdata: ByteArray): Int {
        var ac = 0
        for (i in dnskeyRdata.indices) {
            ac += if ((i and 1) != 0) {
                dnskeyRdata[i].toInt() and 0xff
            } else {
                (dnskeyRdata[i].toInt() and 0xff) shl 8
            }
        }
        ac += (ac shr 16) and 0xffff
        return ac and 0xffff
    }

    fun keyTag(key: DnskeyRdata): Int = keyTag(key.toBytes())

    fun dsDigest(ownerName: String, key: DnskeyRdata, digestType: Int): ByteArray {
        val nameWire = DnsMessage.encodeNameUncompressed(ownerName)
        val md = when (digestType) {
            DsRdata.DIGEST_SHA1 -> MessageDigest.getInstance("SHA-1")
            DsRdata.DIGEST_SHA256 -> MessageDigest.getInstance("SHA-256")
            else -> throw DnsException("Unsupported DS digest $digestType")
        }
        md.update(nameWire)
        md.update(key.toBytes())
        return md.digest()
    }

    fun matchesDs(ownerName: String, key: DnskeyRdata, ds: DsRdata): Boolean {
        if (key.algorithm != ds.algorithm) return false
        if (keyTag(key) != ds.keyTag) return false
        val dig = try {
            dsDigest(ownerName, key, ds.digestType)
        } catch (_: Exception) {
            return false
        }
        return dig.contentEquals(ds.digest)
    }
}
