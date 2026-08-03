package org.kotlintor.crypto

import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.kotlintor.util.SecureRandomSource

data class X25519KeyPair(val privateKey: ByteArray, val publicKey: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is X25519KeyPair &&
            privateKey.contentEquals(other.privateKey) &&
            publicKey.contentEquals(other.publicKey)

    override fun hashCode(): Int = privateKey.contentHashCode() xor publicKey.contentHashCode()
}

object Curve25519 {
    fun generateKeyPair(): X25519KeyPair {
        val priv = SecureRandomSource.nextBytes(32)
        X25519.clampPrivateKey(priv)
        val pub = ByteArray(32)
        X25519.generatePublicKey(priv, 0, pub, 0)
        return X25519KeyPair(priv, pub)
    }

    fun sharedSecret(privateKey: ByteArray, peerPublic: ByteArray): ByteArray {
        require(privateKey.size == 32 && peerPublic.size == 32)
        val out = ByteArray(32)
        X25519.calculateAgreement(privateKey, 0, peerPublic, 0, out, 0)
        return out
    }

    fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        val pub = ByteArray(32)
        X25519.generatePublicKey(privateKey.copyOf().also { X25519.clampPrivateKey(it) }, 0, pub, 0)
        return pub
    }
}

data class Ed25519KeyPair(val privateKey: ByteArray, val publicKey: ByteArray)

object Ed25519Keys {
    fun generate(): Ed25519KeyPair {
        val priv = SecureRandomSource.nextBytes(Ed25519.SECRET_KEY_SIZE)
        val pub = ByteArray(Ed25519.PUBLIC_KEY_SIZE)
        Ed25519.generatePublicKey(priv, 0, pub, 0)
        return Ed25519KeyPair(priv, pub)
    }

    fun sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        val sig = ByteArray(Ed25519.SIGNATURE_SIZE)
        Ed25519.sign(privateKey, 0, message, 0, message.size, sig, 0)
        return sig
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        Ed25519.verify(signature, 0, publicKey, 0, message, 0, message.size)
}
