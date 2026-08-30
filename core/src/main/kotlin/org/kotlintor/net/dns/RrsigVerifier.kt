package org.kotlintor.net.dns

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import java.security.Security

/**
 * Canonicalize RRsets and verify RRSIGs (RFC 4034 / 4035).
 * Algorithms: RSASHA256 (8), ECDSAP256SHA256 (13) per RFC 8624.
 */
object RrsigVerifier {
    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun verifyRrset(
        ownerName: String,
        type: Int,
        records: List<DnsRr>,
        rrsigs: List<RrsigRdata>,
        dnskeys: List<DnskeyRdata>,
        nowEpochSec: Long = System.currentTimeMillis() / 1000,
    ): Boolean {
        if (records.isEmpty() || rrsigs.isEmpty() || dnskeys.isEmpty()) return false
        val owner = DnsMessage.canonicalizeName(ownerName)
        for (sig in rrsigs) {
            if (sig.typeCovered != type) continue
            if (!DnsTypes.supportedAlg(sig.algorithm)) continue
            if (nowEpochSec < sig.inception || nowEpochSec > sig.expiration) continue
            val keys = dnskeys.filter {
                it.algorithm == sig.algorithm && DnssecCrypto.keyTag(it) == sig.keyTag
            }
            for (key in keys) {
                if (verifyOne(owner, type, records, sig, key)) return true
            }
        }
        return false
    }

    private fun verifyOne(
        owner: String,
        type: Int,
        records: List<DnsRr>,
        sig: RrsigRdata,
        key: DnskeyRdata,
    ): Boolean {
        val signed = try {
            buildSignedData(owner, type, records, sig)
        } catch (_: Exception) {
            return false
        }
        return when (sig.algorithm) {
            DnsTypes.ALG_RSASHA256 -> verifyRsaSha256(key.publicKey, signed, sig.signature)
            DnsTypes.ALG_ECDSAP256SHA256 -> verifyEcdsaP256(key.publicKey, signed, sig.signature)
            else -> false
        }
    }

    /**
     * RRSIG RDATA (without signature) || canonical RRset.
     */
    fun buildSignedData(
        owner: String,
        type: Int,
        records: List<DnsRr>,
        sig: RrsigRdata,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        DnsMessage.writeU16(out, sig.typeCovered)
        out.write(sig.algorithm and 0xff)
        out.write(sig.labels and 0xff)
        DnsMessage.writeU32(out, sig.originalTtl)
        DnsMessage.writeU32(out, sig.expiration)
        DnsMessage.writeU32(out, sig.inception)
        DnsMessage.writeU16(out, sig.keyTag)
        out.write(DnsMessage.encodeNameUncompressed(sig.signerName))

        val wildOwner = wildcardOwner(owner, sig.labels)
        val rrWire = records
            .filter { DnsMessage.canonicalizeName(it.name) == owner && it.type == type }
            .map { canonicalizeRr(wildOwner, it, sig.originalTtl) }
            .sortedWith { a, b -> unsignedCompare(a, b) }
        for (rr in rrWire) out.write(rr)
        return out.toByteArray()
    }

    private fun wildcardOwner(owner: String, labels: Int): String {
        val parts = if (owner.isEmpty()) emptyList() else owner.split('.')
        if (parts.size == labels) return owner
        if (parts.size < labels) return owner
        val kept = parts.takeLast(labels)
        return ("*." + kept.joinToString(".")).trimEnd('.')
    }

    private fun canonicalizeRr(owner: String, rr: DnsRr, origTtl: Long): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(DnsMessage.encodeNameUncompressed(owner))
        DnsMessage.writeU16(out, rr.type)
        DnsMessage.writeU16(out, rr.klass)
        DnsMessage.writeU32(out, origTtl)
        val rdata = canonicalizeRdata(rr.type, rr.rdata)
        DnsMessage.writeU16(out, rdata.size)
        out.write(rdata)
        return out.toByteArray()
    }

    /** Lowercase domain names inside rdata for name-bearing types. */
    fun canonicalizeRdata(type: Int, rdata: ByteArray): ByteArray =
        when (type) {
            DnsTypes.NS, DnsTypes.CNAME, DnsTypes.PTR, DnsTypes.NSEC ->
                lowercaseEmbeddedNames(rdata, nameCount = 1)
            DnsTypes.MX -> {
                if (rdata.size < 2) rdata
                else {
                    val out = ByteArrayOutputStream()
                    out.write(rdata, 0, 2)
                    out.write(lowercaseEmbeddedNames(rdata.copyOfRange(2, rdata.size), 1))
                    out.toByteArray()
                }
            }
            DnsTypes.SOA -> lowercaseEmbeddedNames(rdata, nameCount = 2)
            DnsTypes.RRSIG -> rdata // already handled separately
            else -> rdata
        }

    private fun lowercaseEmbeddedNames(rdata: ByteArray, nameCount: Int): ByteArray {
        val buf = ByteBuffer.wrap(rdata).order(ByteOrder.BIG_ENDIAN)
        val out = ByteArrayOutputStream()
        repeat(nameCount) {
            val start = buf.position()
            val name = DnsMessage.readName(buf, rdata)
            out.write(DnsMessage.encodeNameUncompressed(name))
            // consume any unread if compression used — readName already advanced
            if (start == buf.position()) { /* impossible */ }
        }
        val rest = ByteArray(buf.remaining())
        buf.get(rest)
        out.write(rest)
        return out.toByteArray()
    }

    private fun unsignedCompare(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    private fun verifyRsaSha256(pubKeyWire: ByteArray, data: ByteArray, sig: ByteArray): Boolean =
        try {
            val pub = parseRsaDnskey(pubKeyWire)
            val s = Signature.getInstance("SHA256withRSA")
            s.initVerify(pub)
            s.update(data)
            s.verify(sig)
        } catch (_: Exception) {
            false
        }

    private fun verifyEcdsaP256(pubKeyWire: ByteArray, data: ByteArray, sig: ByteArray): Boolean {
        return try {
            if (pubKeyWire.size != 64 || sig.size != 64) return false
            val pub = parseEcdsaP256(pubKeyWire)
            val der = ecdsaRawToDer(sig)
            val s = Signature.getInstance("SHA256withECDSA")
            s.initVerify(pub)
            s.update(data)
            s.verify(der)
        } catch (_: Exception) {
            false
        }
    }

    fun parseRsaDnskey(wire: ByteArray): RSAPublicKey {
        if (wire.isEmpty()) throw DnsException("empty RSA key")
        val expLenField = wire[0].toInt() and 0xff
        val (expLen, offset) = if (expLenField == 0) {
            if (wire.size < 3) throw DnsException("RSA exp len")
            val el = ((wire[1].toInt() and 0xff) shl 8) or (wire[2].toInt() and 0xff)
            el to 3
        } else {
            expLenField to 1
        }
        if (wire.size < offset + expLen + 1) throw DnsException("RSA key truncated")
        val exp = BigInteger(1, wire.copyOfRange(offset, offset + expLen))
        val mod = BigInteger(1, wire.copyOfRange(offset + expLen, wire.size))
        val spec = RSAPublicKeySpec(mod, exp)
        return KeyFactory.getInstance("RSA").generatePublic(spec) as RSAPublicKey
    }

    fun parseEcdsaP256(wire: ByteArray): ECPublicKey {
        require(wire.size == 64)
        val params = ECNamedCurveTable.getParameterSpec("P-256")
        val spec = ECNamedCurveSpec("P-256", params.curve, params.g, params.n, params.h)
        val x = BigInteger(1, wire.copyOfRange(0, 32))
        val y = BigInteger(1, wire.copyOfRange(32, 64))
        val point = ECPoint(x, y)
        val keySpec = ECPublicKeySpec(point, spec)
        return KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
            .generatePublic(keySpec) as ECPublicKey
    }

    /** Convert R||S (32+32) to DER SEQUENCE. */
    fun ecdsaRawToDer(raw: ByteArray): ByteArray {
        require(raw.size == 64)
        fun encInt(half: ByteArray): ByteArray {
            var v = half.dropWhile { it == 0.toByte() }.toByteArray()
            if (v.isEmpty()) v = byteArrayOf(0)
            if (v[0].toInt() and 0x80 != 0) v = byteArrayOf(0) + v
            return byteArrayOf(0x02, v.size.toByte()) + v
        }
        val r = encInt(raw.copyOfRange(0, 32))
        val s = encInt(raw.copyOfRange(32, 64))
        val body = r + s
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
