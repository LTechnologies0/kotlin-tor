package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.util.constantTimeEquals
import java.security.PublicKey
import java.time.Instant

/**
 * Live v3 consensus signature verification (dir-spec).
 *
 * Digest region: bytes from the start of the document through the first
 * `"directory-signature "` (including the trailing space). SHA1 signatures
 * are RSA-PKCS1 checksig of SHA1(region); `sha256` uses SHA256(region).
 *
 * Authority certificates must be **pinned** to [knownAuthorityFingerprints]
 * (DefaultAuthorities v3 identity fingerprints, or TestingTorNetwork set).
 * Quorum is strictly more than half of known authorities (`n/2 + 1`).
 */
object ConsensusVerifier {
    data class Result(
        val ok: Boolean,
        val validCount: Int,
        val required: Int,
        val reason: String,
    )

    fun signedRegion(raw: String): ByteArray {
        val idx = raw.indexOf("directory-signature ")
        require(idx >= 0) { "consensus has no directory-signature" }
        return raw.substring(0, idx + "directory-signature ".length).toByteArray(Charsets.US_ASCII)
    }

    fun parseSignatures(raw: String): List<DetachedSignatures.DocumentSignature> {
        val idx = raw.indexOf("directory-signature ")
        if (idx < 0) return emptyList()
        return DetachedSignatures.parse(raw.substring(idx)).signatures
    }

    fun verify(
        consensus: Consensus,
        certs: Collection<AuthorityCert.Parsed>,
        knownAuthorityFingerprints: Set<String>,
        now: Instant = Instant.now(),
        minValidAfter: Instant? = null,
        nAuthorities: Int = knownAuthorityFingerprints.size,
    ): Result {
        if (!consensus.isValidAt(now)) {
            return Result(
                false, 0, DirAuthQuorum.requiredSignatures(nAuthorities.coerceAtLeast(1)),
                "consensus not live: valid-after=${consensus.validAfter} valid-until=${consensus.validUntil} now=$now",
            )
        }
        if (minValidAfter != null && consensus.validAfter.isBefore(minValidAfter)) {
            return Result(
                false, 0, DirAuthQuorum.requiredSignatures(nAuthorities.coerceAtLeast(1)),
                "consensus older than cached valid-after=$minValidAfter",
            )
        }
        val known = knownAuthorityFingerprints.map { it.replace(" ", "").lowercase() }.toSet()
        if (known.isEmpty()) {
            return Result(false, 0, 1, "no pinned authority fingerprints")
        }
        val pinnedCerts = certs.filter { cert ->
            val fp = cert.fingerprintHex.replace(" ", "").lowercase()
            fp in known && AuthorityCert.verify(cert)
        }
        if (pinnedCerts.isEmpty()) {
            return Result(false, 0, DirAuthQuorum.requiredSignatures(known.size), "no pinned authority certificates")
        }
        val region = runCatching { signedRegion(consensus.raw) }.getOrElse {
            return Result(false, 0, DirAuthQuorum.requiredSignatures(known.size), it.message ?: "no signed region")
        }
        val sha1 = Digests.sha1(region)
        val sha256 = Digests.sha256(region)
        val sigs = parseSignatures(consensus.raw)
        val validIds = linkedSetOf<String>()
        for (sig in sigs) {
            val id = sig.identityHex.replace(" ", "").lowercase()
            if (id !in known) continue
            val cert = pinnedCerts.firstOrNull {
                it.fingerprintHex.replace(" ", "").equals(id, ignoreCase = true)
            } ?: continue
            if (AuthCert.authorityCertIsDenylisted(sig.signingKeyDigestHex)) continue
            val skHex = cert.signingKeyDigest.joinToString("") { "%02x".format(it) }
            if (sig.signingKeyDigestHex.isNotBlank() &&
                !sig.signingKeyDigestHex.equals(skHex, ignoreCase = true)
            ) {
                continue
            }
            val pub = AuthorityCert.rsaPublicKeyFromPkcs1(cert.signingPkcs1)
            val digest = when (sig.algorithm.lowercase()) {
                "sha1", "sha-1" -> sha1
                "sha256", "sha-256" -> sha256
                else -> continue
            }
            if (verifyRsaChecksig(pub, sig.signature, digest)) {
                validIds += id
            }
        }
        val required = DirAuthQuorum.requiredSignatures(nAuthorities.coerceAtLeast(known.size).coerceAtLeast(1))
        val ok = validIds.size >= required
        return Result(
            ok = ok,
            validCount = validIds.size,
            required = required,
            reason = if (ok) {
                "quorum ${validIds.size}>=$required"
            } else {
                "need $required valid pinned signatures, got ${validIds.size}"
            },
        )
    }

    fun verifyRsaChecksig(pub: PublicKey, signature: ByteArray, digest: ByteArray): Boolean {
        return try {
            val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, pub)
            constantTimeEquals(cipher.doFinal(signature), digest)
        } catch (_: Exception) {
            false
        }
    }
}
