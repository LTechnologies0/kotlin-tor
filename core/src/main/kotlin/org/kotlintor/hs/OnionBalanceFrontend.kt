package org.kotlintor.hs

import org.kotlintor.crypto.Ed25519KeyPair
import org.kotlintor.crypto.Ed25519Keys
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * OnionBalance-style frontend: aggregate backend intro points, sign with a
 * dedicated frontend identity, and rate-limit INTRODUCE2 admissions.
 *
 * Not a full OnionBalance daemon (no hash-ring coordinator IPC); covers the
 * control-plane pieces apps need to publish one HA .onion from N backends.
 */
class OnionBalanceFrontend(
    val frontendIdentity: Ed25519KeyPair,
    val backends: MutableList<OnionBalance.Backend> = mutableListOf(),
    val maxIntros: Int = 10,
    val introRatePerMin: Int = 200,
) {
    private val rate = HsIntroRateLimit(maxPerMinute = introRatePerMin)

    val address: String get() = OnionAddressV3.encode(frontendIdentity.publicKey)

    fun addBackend(backend: OnionBalance.Backend) {
        backends.removeAll { it.name == backend.name }
        backends += backend
    }

    fun buildDescriptor(
        period: HsTimePeriod,
        revisionCounter: Long,
        lifetimeMinutes: Int = 180,
        powChallenge: HsPow.Challenge? = null,
        authorizedClients: List<HsClientAuth.ClientCred> = emptyList(),
    ): String {
        val input = HsDescriptorBuildInput(
            publicIdentity = frontendIdentity.publicKey,
            privateIdentitySeed = frontendIdentity.privateKey,
            period = period,
            revisionCounter = revisionCounter,
            lifetimeMinutes = lifetimeMinutes,
            introPoints = OnionBalance.mergeIntroPoints(backends, maxIntros),
            powChallenge = powChallenge,
            authorizedClients = authorizedClients,
        )
        return HsDescriptorCodec.build(input)
    }

    /** Persist frontend secret key (32-byte seed) under [dir]/hs_ed25519_secret_key`. */
    fun saveKeys(dir: Path) {
        Files.createDirectories(dir)
        Files.write(dir.resolve("hs_ed25519_secret_key"), frontendIdentity.privateKey)
        Files.write(dir.resolve("hs_ed25519_public_key"), frontendIdentity.publicKey)
        Files.writeString(dir.resolve("hostname"), "$address\n")
    }

    fun allowIntroduce(): Boolean = rate.tryAdmit()

    companion object {
        fun generate(): OnionBalanceFrontend =
            OnionBalanceFrontend(Ed25519Keys.generate())

        fun load(dir: Path): OnionBalanceFrontend {
            val seed = Files.readAllBytes(dir.resolve("hs_ed25519_secret_key"))
            val pub = Files.readAllBytes(dir.resolve("hs_ed25519_public_key"))
            return OnionBalanceFrontend(Ed25519KeyPair(seed, pub))
        }
    }
}

/** Per-service INTRODUCE2 admission rate limit (HiddenServiceMaxStreams-style lite). */
class HsIntroRateLimit(
    private val maxPerMinute: Int = 200,
) {
    private val windowStart = AtomicLong(System.currentTimeMillis())
    private val count = AtomicInteger(0)

    fun tryAdmit(): Boolean {
        val now = System.currentTimeMillis()
        if (now - windowStart.get() > 60_000) {
            windowStart.set(now)
            count.set(0)
        }
        return count.incrementAndGet() <= maxPerMinute
    }

    fun current(): Int = count.get()
}

/** Multiplex rate limits keyed by onion service id. */
object HsIntroRateLimits {
    private val byService = ConcurrentHashMap<String, HsIntroRateLimit>()

    fun forService(onionId: String, maxPerMinute: Int = 200): HsIntroRateLimit =
        byService.getOrPut(onionId.lowercase()) { HsIntroRateLimit(maxPerMinute) }
}
