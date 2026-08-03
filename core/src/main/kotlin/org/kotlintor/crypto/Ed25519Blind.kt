package org.kotlintor.crypto

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.lang.reflect.Constructor
import java.lang.reflect.Method
import java.math.BigInteger
import java.security.MessageDigest

/**
 * Ed25519 public/private key blinding via BouncyCastle internals (rend-spec-v3 A.2).
 *
 * Blinded secret keys are expanded (scalar ‖ hash_prefix). BC's
 * [Ed25519.ExpandedKey.sign] re-prunes the scalar, which breaks Tor blinding, so
 * signing goes through [Ed25519.implSign] with the unclamped blinded scalar.
 */
object Ed25519Blind {
    private val L: BigInteger =
        BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)

    private val RH_BLIND_STRING = "Derive temporary signing key hash input".toByteArray()

    private val pointAffineCl = Class.forName("org.bouncycastle.math.ec.rfc8032.Ed25519\$PointAffine")
    private val pointAccumCl = Class.forName("org.bouncycastle.math.ec.rfc8032.Ed25519\$PointAccum")

    private val affineCtor: Constructor<*> = pointAffineCl.getDeclaredConstructor().also { it.isAccessible = true }
    private val accumCtor: Constructor<*> = pointAccumCl.getDeclaredConstructor().also { it.isAccessible = true }

    private val decodePointVar: Method =
        Ed25519::class.java.getDeclaredMethod(
            "decodePointVar",
            ByteArray::class.java,
            Boolean::class.javaPrimitiveType,
            pointAffineCl,
        ).also { it.isAccessible = true }

    private val scalarMult: Method =
        Ed25519::class.java.getDeclaredMethod(
            "scalarMult",
            ByteArray::class.java,
            pointAffineCl,
            pointAccumCl,
        ).also { it.isAccessible = true }

    private val encodeResult: Method =
        Ed25519::class.java.getDeclaredMethod(
            "encodeResult",
            pointAccumCl,
            ByteArray::class.java,
            Int::class.javaPrimitiveType,
        ).also { it.isAccessible = true }

    private val implSign: Method =
        Ed25519::class.java.getDeclaredMethod(
            "implSign",
            org.bouncycastle.crypto.Digest::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java,
            Int::class.javaPrimitiveType,
            ByteArray::class.java,
            Byte::class.javaPrimitiveType,
            ByteArray::class.java,
            Int::class.javaPrimitiveType,
            Int::class.javaPrimitiveType,
            ByteArray::class.java,
            Int::class.javaPrimitiveType,
        ).also { it.isAccessible = true }

    private val scalarMultBaseEncoded: Method =
        Ed25519::class.java.getDeclaredMethod(
            "scalarMultBaseEncoded",
            ByteArray::class.java,
            ByteArray::class.java,
            Int::class.javaPrimitiveType,
        ).also { it.isAccessible = true }

    data class ExpandedSecret(
        /** Little-endian scalar (32) ‖ hash_prefix (32). */
        val bytes: ByteArray,
        val publicKey: ByteArray,
    ) {
        val scalar: ByteArray get() = bytes.copyOfRange(0, 32)
        val hashPrefix: ByteArray get() = bytes.copyOfRange(32, 64)

        override fun equals(other: Any?): Boolean =
            other is ExpandedSecret && bytes.contentEquals(other.bytes) && publicKey.contentEquals(other.publicKey)

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    /** Clamp blinding factor per Ed25519 / rend-spec A.2, then A' = h·A. */
    fun blindPublicKey(publicKey: ByteArray, blindingFactorUnclamped: ByteArray): ByteArray {
        require(publicKey.size == 32)
        require(blindingFactorUnclamped.size == 32)
        val h = clampScalarBytes(blindingFactorUnclamped)
        return scalarMultPoint(h, publicKey)
    }

    fun expandSecretKey(seed: ByteArray): ExpandedSecret {
        require(seed.size == 32)
        val digest = MessageDigest.getInstance("SHA-512").digest(seed)
        val scalar = clampScalarBytes(digest.copyOfRange(0, 32))
        // Match dalek: interpret clamped bytes as LE integer mod L, re-encode.
        val scalarCanon = bigIntToLe32(leBytesToBigInt(scalar).mod(L))
        val hashPrefix = digest.copyOfRange(32, 64)
        val expanded = scalarCanon + hashPrefix
        val pub = publicFromScalar(scalarCanon)
        return ExpandedSecret(expanded, pub)
    }

    /**
     * Blind an expanded identity keypair. [blindingFactorUnclamped] is `h = H(...)`
     * before clamping (rend-spec A.2).
     */
    fun blindKeypair(expanded: ExpandedSecret, blindingFactorUnclamped: ByteArray): ExpandedSecret {
        require(blindingFactorUnclamped.size == 32)
        val h = clampScalarBytes(blindingFactorUnclamped)
        val a = leBytesToBigInt(expanded.scalar).mod(L)
        val factor = leBytesToBigInt(h).mod(L)
        val blindedScalar = bigIntToLe32(a.multiply(factor).mod(L))
        val sha = MessageDigest.getInstance("SHA-512")
        sha.update(RH_BLIND_STRING)
        sha.update(expanded.hashPrefix)
        val blindedPrefix = sha.digest().copyOfRange(0, 32)
        val bytes = blindedScalar + blindedPrefix
        val pub = publicFromScalar(blindedScalar)
        return ExpandedSecret(bytes, pub)
    }

    /** Sign [message] with an expanded (possibly blinded) secret key — no re-prune. */
    fun signExpanded(expanded: ExpandedSecret, message: ByteArray): ByteArray {
        val h = expanded.bytes.copyOf()
        val s = expanded.scalar.copyOf()
        val pk = expanded.publicKey
        val sig = ByteArray(Ed25519.SIGNATURE_SIZE)
        implSign.invoke(
            null,
            SHA512Digest(),
            h,
            s,
            pk,
            0,
            null,
            0.toByte(),
            message,
            0,
            message.size,
            sig,
            0,
        )
        return sig
    }

    fun publicFromScalar(scalarLe: ByteArray): ByteArray {
        require(scalarLe.size == 32)
        val out = ByteArray(32)
        scalarMultBaseEncoded.invoke(null, scalarLe.copyOf(), out, 0)
        return out
    }

    private fun scalarMultPoint(scalarClamped: ByteArray, publicKey: ByteArray): ByteArray {
        val affine = affineCtor.newInstance()
        val ok = decodePointVar.invoke(null, publicKey, false, affine) as Boolean
        check(ok) { "invalid ed25519 public key for blinding" }
        val accum = accumCtor.newInstance()
        scalarMult.invoke(null, scalarClamped, affine, accum)
        val out = ByteArray(32)
        val n = encodeResult.invoke(null, accum, out, 0) as Int
        check(n != 0) { "ed25519 blinding encode failed" }
        return out
    }

    private fun clampScalarBytes(raw: ByteArray): ByteArray {
        val h = raw.copyOf(32)
        h[0] = (h[0].toInt() and 248).toByte()
        h[31] = (h[31].toInt() and 63).toByte()
        h[31] = (h[31].toInt() or 64).toByte()
        return h
    }

    private fun leBytesToBigInt(le: ByteArray): BigInteger =
        BigInteger(1, le.reversedArray())

    private fun bigIntToLe32(v: BigInteger): ByteArray {
        val be = v.toByteArray()
        val le = ByteArray(32)
        // be is big-endian two's complement; copy least-significant 32 bytes
        var bi = be.size - 1
        var li = 0
        while (li < 32 && bi >= 0) {
            le[li++] = be[bi--]
        }
        return le
    }
}
