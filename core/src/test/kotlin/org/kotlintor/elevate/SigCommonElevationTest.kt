package org.kotlintor.elevate

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.crypto.Digests
import org.kotlintor.dir.SigCommon
import java.security.KeyPairGenerator
import javax.crypto.Cipher

/**
 * Elevates `L1:feature/dirparse/sigcommon.c` toward D3.
 *
 * Evidence: hash-impl helper line-start rules, dual digests, PKCS1 checksig.
 */
class SigCommonElevationTest {
    @Test
    fun `hash_impl_helper requires line start and end char`() {
        val good = "router-signature\nbody\n-----BEGIN SIGNATURE-----\n"
        val bounds = SigCommon.getHashImplHelper(good, "router-signature", "-----BEGIN SIGNATURE-----")
        assertNotNull(bounds)
        assertEquals(0, bounds!!.start)

        val badIndent = "xrouter-signature\n-----BEGIN SIGNATURE-----\n"
        assertNull(SigCommon.getHashImplHelper(badIndent, "router-signature", "-----BEGIN SIGNATURE-----"))

        val missingEnd = "router-signature\nnope\n"
        assertNull(SigCommon.getHashImplHelper(missingEnd, "router-signature", "-----BEGIN SIGNATURE-----"))
    }

    @Test
    fun `get_hash_impl and get_hashes_impl`() {
        val doc = "network-status-version 3\ndirectory-footer\n"
        val sha1 = SigCommon.getHashImpl(doc, "network-status-version", "directory-footer")
        assertNotNull(sha1)
        assertEquals(20, sha1!!.size)
        val dual = SigCommon.getHashesImpl(doc, "network-status-version", "directory-footer")
        assertNotNull(dual)
        assertTrue(sha1.contentEquals(dual!!.first))
        assertEquals(32, dual.second.size)
        val region = doc // whole hashed region ends after newline following directory-footer
        val expected = Digests.sha1(
            SigCommon.getHashImplHelper(doc, "network-status-version", "directory-footer")!!.let {
                doc.substring(it.start, it.endExclusive).toByteArray(Charsets.US_ASCII)
            },
        )
        assertTrue(sha1.contentEquals(expected))
        @Suppress("UNUSED_VARIABLE")
        val _u = region
    }

    @Test
    fun `check_signature_token PKCS1 recovers digest`() {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val digest = Digests.sha1("hello-dir".toByteArray())
        val sigBytes = Cipher.getInstance("RSA/ECB/PKCS1Padding").run {
            init(Cipher.ENCRYPT_MODE, kp.private)
            doFinal(digest)
        }
        val tok = SigCommon.SignatureToken("SIGNATURE", sigBytes)
        assertTrue(SigCommon.checkSignatureToken(digest, tok, kp.public))
        assertFalse(
            SigCommon.checkSignatureToken(
                digest,
                tok.copy(objectType = "WRONG"),
                kp.public,
            ),
        )
        assertTrue(
            SigCommon.checkSignatureToken(
                digest,
                tok.copy(objectType = "WRONG"),
                kp.public,
                flags = SigCommon.CST_NO_CHECK_OBJTYPE,
            ),
        )
        val bad = digest.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertFalse(SigCommon.checkSignatureToken(bad, tok, kp.public))
    }

    @Test
    fun `signed_digest_equals length aware`() {
        val a = byteArrayOf(1, 2, 3, 4)
        val b = byteArrayOf(1, 2, 3, 9)
        assertTrue(SigCommon.signedDigestEquals(a, b, 3))
        assertFalse(SigCommon.signedDigestEquals(a, b, 4))
    }
}
