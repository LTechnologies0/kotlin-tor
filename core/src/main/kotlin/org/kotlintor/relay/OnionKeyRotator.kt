package org.kotlintor.relay

import org.kotlintor.crypto.Curve25519
import org.kotlintor.crypto.X25519KeyPair
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

/**
 * Onion key (ntor) rotation — torrc OnionKeyLifetime + OnionKeyGracePeriod.
 * Keeps current + previous key so CREATE2 during grace still works.
 */
class OnionKeyRotator(
    private val keysDir: Path,
    private val lifetimeDays: Int,
    /** Days previous key remains accepted after rotation (OnionKeyGracePeriod). */
    private val gracePeriodDays: Int = 7,
) {
    data class KeySet(
        val current: X25519KeyPair,
        val previous: X25519KeyPair?,
        val rotatedAtEpochSec: Long,
    )

    private val state = AtomicReference<KeySet?>(null)

    fun loadOrGenerate(): KeySet {
        Files.createDirectories(keysDir)
        val curPath = keysDir.resolve("secret_onion_key_ntor")
        val prevPath = keysDir.resolve("secret_onion_key_ntor.old")
        val metaPath = keysDir.resolve("onion_key_rotated_at")
        val current = if (Files.exists(curPath) && Files.size(curPath) == 32L) {
            val priv = Files.readAllBytes(curPath)
            X25519KeyPair(priv, Curve25519.publicFromPrivate(priv))
        } else {
            Curve25519.generateKeyPair().also { Files.write(curPath, it.privateKey) }
        }
        val previous = if (Files.exists(prevPath) && Files.size(prevPath) == 32L) {
            val priv = Files.readAllBytes(prevPath)
            X25519KeyPair(priv, Curve25519.publicFromPrivate(priv))
        } else {
            null
        }
        val rotatedAt = if (Files.exists(metaPath)) {
            Files.readString(metaPath).trim().toLongOrNull() ?: Instant.now().epochSecond
        } else {
            Instant.now().epochSecond.also { Files.writeString(metaPath, it.toString()) }
        }
        return KeySet(current, previous, rotatedAt).also { state.set(it) }
    }

    fun current(): X25519KeyPair = state.get()?.current ?: loadOrGenerate().current

    fun previous(): X25519KeyPair? = state.get()?.previous

    /** Rotate if lifetime exceeded; returns true if rotated. */
    fun maybeRotate(): Boolean {
        val st = state.get() ?: loadOrGenerate()
        val ageSec = Instant.now().epochSecond - st.rotatedAtEpochSec
        if (ageSec < lifetimeDays * 86_400L) return false
        val curPath = keysDir.resolve("secret_onion_key_ntor")
        val prevPath = keysDir.resolve("secret_onion_key_ntor.old")
        val metaPath = keysDir.resolve("onion_key_rotated_at")
        Files.write(prevPath, st.current.privateKey)
        val fresh = Curve25519.generateKeyPair()
        Files.write(curPath, fresh.privateKey)
        val now = Instant.now().epochSecond
        Files.writeString(metaPath, now.toString())
        state.set(KeySet(fresh, st.current, now))
        return true
    }

    /** Accept CREATE2 against current or previous onion key (within grace). */
    fun matchesOnionPublic(pub: ByteArray): X25519KeyPair? {
        val st = state.get() ?: return null
        if (st.current.publicKey.contentEquals(pub)) return st.current
        val prev = st.previous ?: return null
        if (!prev.publicKey.contentEquals(pub)) return null
        val ageSec = Instant.now().epochSecond - st.rotatedAtEpochSec
        if (ageSec > gracePeriodDays * 86_400L) return null
        return prev
    }
}
