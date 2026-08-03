package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.util.toHex
import java.util.Base64

/**
 * Detached consensus signatures (C Tor `ns_detached_signatures_t` / `dsigs_parse.c`).
 *
 * Format (dir-spec): preamble digests + `directory-signature` PEM objects per authority.
 * Signing here uses Ed25519 over SHA-256(consensus body) for TestingTorNetwork /
 * local dirauth — not a drop-in for live v3 authority RSA/Ed cert chains.
 */
object DetachedSignatures {
    data class DocumentSignature(
        val algorithm: String,
        val identityHex: String,
        val signingKeyDigestHex: String,
        val signature: ByteArray,
    )

    data class Detached(
        val validAfter: String?,
        val freshUntil: String?,
        val validUntil: String?,
        /** flavor → hex digest (sha256 of consensus body for that flavor). */
        val digests: Map<String, String>,
        val signatures: List<DocumentSignature>,
    )

    fun digestBody(body: String): ByteArray = Digests.sha256(body.toByteArray(Charsets.US_ASCII))

    fun digestHex(body: String): String = digestBody(body).toHex().lowercase()

    fun formatDetached(
        body: String,
        validAfter: String,
        freshUntil: String,
        validUntil: String,
        signatures: List<DocumentSignature>,
        flavor: String = "ns",
    ): String = buildString {
        appendLine("consensus-digest ${digestHex(body)}")
        if (flavor != "ns") appendLine("additional-digest $flavor sha256 ${digestHex(body)}")
        appendLine("valid-after $validAfter")
        appendLine("fresh-until $freshUntil")
        appendLine("valid-until $validUntil")
        for (s in signatures) {
            appendLine(
                "directory-signature ${s.algorithm} ${s.identityHex.lowercase()} " +
                    s.signingKeyDigestHex.lowercase(),
            )
            appendLine("-----BEGIN SIGNATURE-----")
            val b64 = Base64.getEncoder().encodeToString(s.signature)
            b64.chunked(64).forEach { appendLine(it) }
            appendLine("-----END SIGNATURE-----")
        }
    }

    fun parse(text: String): Detached {
        var validAfter: String? = null
        var freshUntil: String? = null
        var validUntil: String? = null
        val digests = linkedMapOf<String, String>()
        val sigs = ArrayList<DocumentSignature>()
        val lines = text.lineSequence().iterator()
        while (lines.hasNext()) {
            val line = lines.next().trimEnd()
            when {
                line.startsWith("consensus-digest ") ->
                    digests["ns"] = line.removePrefix("consensus-digest ").trim().lowercase()
                line.startsWith("additional-digest ") -> {
                    val p = line.removePrefix("additional-digest ").trim().split(Regex("\\s+"))
                    if (p.size >= 3) digests[p[0]] = p[2].lowercase()
                }
                line.startsWith("valid-after ") -> validAfter = line.removePrefix("valid-after ").trim()
                line.startsWith("fresh-until ") -> freshUntil = line.removePrefix("fresh-until ").trim()
                line.startsWith("valid-until ") -> validUntil = line.removePrefix("valid-until ").trim()
                line.startsWith("directory-signature ") -> {
                    val p = line.removePrefix("directory-signature ").trim().split(Regex("\\s+"))
                    require(p.size >= 3) { "bad directory-signature line" }
                    val alg = p[0]
                    val id = p[1]
                    val sk = p[2]
                    val pem = StringBuilder()
                    var inPem = false
                    while (lines.hasNext()) {
                        val l = lines.next()
                        if (l.contains("BEGIN SIGNATURE")) {
                            inPem = true
                            continue
                        }
                        if (l.contains("END SIGNATURE")) break
                        if (inPem) pem.append(l.trim())
                    }
                    val sig = Base64.getDecoder().decode(pem.toString())
                    sigs += DocumentSignature(alg, id, sk, sig)
                }
            }
        }
        return Detached(validAfter, freshUntil, validUntil, digests, sigs)
    }

    /**
     * Sign consensus [body] with Ed25519 authority key (testing / local dirauth).
     */
    fun signEd25519(
        body: String,
        identityHex: String,
        privateKey: ByteArray,
        publicKey: ByteArray = run {
            val pub = ByteArray(32)
            org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(privateKey, 0, pub, 0)
            pub
        },
    ): DocumentSignature {
        val digest = digestBody(body)
        val sig = Ed25519Keys.sign(privateKey, digest)
        val skDigest = Digests.sha256(publicKey).toHex().lowercase()
        return DocumentSignature("ed25519", identityHex.lowercase(), skDigest, sig)
    }

    fun verifyEd25519(body: String, publicKey: ByteArray, signature: ByteArray): Boolean =
        Ed25519Keys.verify(publicKey, digestBody(body), signature)

    /**
     * Legacy / sha1 RSA directory-signature (C Tor vote path):
     * digest = SHA1(body_through_footer + "directory-signature "),
     * signature = RSA-PKCS1 encrypt of digest with signing key.
     */
    fun sha1DigestForSignature(body: String): ByteArray {
        val trimmed = body.trimEnd() + "\n"
        val prefix = "directory-signature "
        return Digests.sha1((trimmed + prefix).toByteArray(Charsets.US_ASCII))
    }

    fun signSha1Rsa(
        body: String,
        identityFingerprintHex: String,
        signingKeyDigestHex: String,
        signingPrivateKey: java.security.PrivateKey,
    ): DocumentSignature {
        val digest = sha1DigestForSignature(body)
        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, signingPrivateKey)
        val sig = cipher.doFinal(digest)
        return DocumentSignature(
            algorithm = "sha1",
            identityHex = identityFingerprintHex.lowercase(),
            signingKeyDigestHex = signingKeyDigestHex.lowercase(),
            signature = sig,
        )
    }

    fun verifySha1Rsa(
        body: String,
        signingPublicKey: java.security.PublicKey,
        signature: ByteArray,
    ): Boolean {
        val digest = sha1DigestForSignature(body)
        return try {
            val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, signingPublicKey)
            cipher.doFinal(signature).contentEquals(digest)
        } catch (_: Exception) {
            false
        }
    }

    /** Attach signatures to a consensus body (appends directory-signature blocks). */
    fun attachToConsensus(body: String, signatures: List<DocumentSignature>): String = buildString {
        append(body.trimEnd())
        append('\n')
        for (s in signatures) {
            appendLine(
                "directory-signature ${s.algorithm} ${s.identityHex.lowercase()} " +
                    s.signingKeyDigestHex.lowercase(),
            )
            appendLine("-----BEGIN SIGNATURE-----")
            Base64.getEncoder().encodeToString(s.signature).chunked(64).forEach { appendLine(it) }
            appendLine("-----END SIGNATURE-----")
        }
    }
}
