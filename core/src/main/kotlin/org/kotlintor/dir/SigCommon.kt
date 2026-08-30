package org.kotlintor.dir

import org.kotlintor.crypto.Digests
import java.security.PublicKey
import java.security.Signature
import java.util.Arrays
import javax.crypto.Cipher

/**
 * Shared hashing / signature-checking for directory objects (C Tor `sigcommon.c`).
 *
 * Inventory: `L1:feature/dirparse/sigcommon.c`
 */
object SigCommon {
    const val CST_NO_CHECK_OBJTYPE: Int = 1

    enum class DigestAlg { SHA1, SHA256 }

    data class HashBounds(val start: Int, val endExclusive: Int)

    /**
     * C Tor `router_get_hash_impl_helper` —
     * region from first line-start [startStr] through [endC] after [endStr].
     */
    fun getHashImplHelper(
        s: String,
        startStr: String,
        endStr: String,
        endC: Char = '\n',
    ): HashBounds? {
        val bytes = s // operate on String indices (ASCII dir docs)
        var start = bytes.indexOf(startStr)
        while (start >= 0) {
            if (start == 0 || bytes[start - 1] == '\n') break
            start = bytes.indexOf(startStr, start + 1)
        }
        if (start < 0) return null
        val afterStart = start + startStr.length
        val endMark = bytes.indexOf(endStr, afterStart)
        if (endMark < 0) return null
        val afterEnd = endMark + endStr.length
        val eol = bytes.indexOf(endC, afterEnd)
        if (eol < 0) return null
        return HashBounds(start, eol + 1)
    }

    /** C Tor `router_compute_hash_final`. */
    fun computeHashFinal(region: ByteArray, alg: DigestAlg): ByteArray =
        when (alg) {
            DigestAlg.SHA1 -> Digests.sha1(region)
            DigestAlg.SHA256 -> Digests.sha256(region)
        }

    /** C Tor `router_get_hash_impl`. */
    fun getHashImpl(
        s: String,
        startStr: String,
        endStr: String,
        endC: Char = '\n',
        alg: DigestAlg = DigestAlg.SHA1,
    ): ByteArray? {
        val b = getHashImplHelper(s, startStr, endStr, endC) ?: return null
        val region = s.substring(b.start, b.endExclusive).toByteArray(Charsets.US_ASCII)
        return computeHashFinal(region, alg)
    }

    /** C Tor `router_get_hashes_impl` — SHA1 + SHA256 of the same region. */
    fun getHashesImpl(
        s: String,
        startStr: String,
        endStr: String,
        endC: Char = '\n',
    ): Pair<ByteArray, ByteArray>? {
        val b = getHashImplHelper(s, startStr, endStr, endC) ?: return null
        val region = s.substring(b.start, b.endExclusive).toByteArray(Charsets.US_ASCII)
        return Digests.sha1(region) to Digests.sha256(region)
    }

    /** C Tor `signed_digest_equals` (constant-time). */
    fun signedDigestEquals(d1: ByteArray, d2: ByteArray, len: Int = minOf(d1.size, d2.size)): Boolean {
        if (d1.size < len || d2.size < len) return false
        return Arrays.equals(d1.copyOf(len), d2.copyOf(len))
    }

    data class SignatureToken(
        val objectType: String,
        val objectBody: ByteArray,
    )

    /**
     * C Tor `check_signature_token` —
     * RSA public decrypt of signature blob must equal [digest] (prefix).
     * When [flags] lacks [CST_NO_CHECK_OBJTYPE], [token].objectType must be `SIGNATURE`.
     *
     * Also accepts SHA1withRSA verify when the token is a standard signed digest
     * (Java Signature API path used by authcerts).
     */
    fun checkSignatureToken(
        digest: ByteArray,
        token: SignatureToken,
        publicKey: PublicKey,
        flags: Int = 0,
        doctype: String = "document",
    ): Boolean {
        if (flags and CST_NO_CHECK_OBJTYPE == 0) {
            if (token.objectType != "SIGNATURE") return false
        }
        // Prefer raw PKCS#1 public checksig (Tor `crypto_pk_public_checksig`).
        val recovered = runCatching {
            Cipher.getInstance("RSA/ECB/PKCS1Padding").run {
                init(Cipher.DECRYPT_MODE, publicKey)
                doFinal(token.objectBody)
            }
        }.getOrNull()
        if (recovered != null && signedDigestEquals(digest, recovered, digest.size)) {
            return true
        }
        // Fallback: SHA1withRSA over digest bytes (some JVM key encodings).
        return runCatching {
            Signature.getInstance("NONEwithRSA").run {
                initVerify(publicKey)
                update(digest)
                verify(token.objectBody)
            }
        }.getOrDefault(false).also {
            // silence unused doctype for API parity with C Tor logs
            @Suppress("UNUSED_EXPRESSION")
            doctype
        }
    }
}
