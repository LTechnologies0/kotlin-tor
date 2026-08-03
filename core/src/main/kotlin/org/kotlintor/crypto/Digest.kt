package org.kotlintor.crypto

import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest

object Digests {
    fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun sha3_256(data: ByteArray): ByteArray {
        val d = SHA3Digest(256)
        d.update(data, 0, data.size)
        return ByteArray(d.digestSize).also { d.doFinal(it, 0) }
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        return ByteArray(mac.macSize).also { mac.doFinal(it, 0) }
    }

    fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA1Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        return ByteArray(mac.macSize).also { mac.doFinal(it, 0) }
    }
}

/** Running SHA-1 digest used for relay cell integrity (legacy onion crypto). */
class RunningSha1 {
    private val digest = SHA1Digest()

    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
        digest.update(data, offset, length)
    }

    fun peek(): ByteArray {
        val copy = SHA1Digest(digest)
        return ByteArray(copy.digestSize).also { copy.doFinal(it, 0) }
    }

    /** Digest of current state plus [extra] without mutating this instance. */
    fun preview(extra: ByteArray): ByteArray {
        val copy = SHA1Digest(digest)
        copy.update(extra, 0, extra.size)
        return ByteArray(copy.digestSize).also { copy.doFinal(it, 0) }
    }
}

/** Running SHA3-256 digest used for v3 onion-service virtual hop relay crypto. */
class RunningSha3 {
    private val digest = SHA3Digest(256)

    fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
        digest.update(data, offset, length)
    }

    fun peek(): ByteArray {
        val copy = SHA3Digest(digest)
        return ByteArray(copy.digestSize).also { copy.doFinal(it, 0) }
    }

    fun preview(extra: ByteArray): ByteArray {
        val copy = SHA3Digest(digest)
        copy.update(extra, 0, extra.size)
        return ByteArray(copy.digestSize).also { copy.doFinal(it, 0) }
    }
}
