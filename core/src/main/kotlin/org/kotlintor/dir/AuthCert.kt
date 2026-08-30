package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Authority certificates (C Tor `authcert.c`).
 *
 * Inventory: `L1:feature/nodelist/authcert.c`
 *
 * Implementation: [AuthorityCert].
 */
object AuthCert {
    fun parse(document: String) = AuthorityCert.parse(document)
    fun verify(parsed: AuthorityCert.Parsed) = AuthorityCert.verify(parsed)

    data class Cached(
        val cert: AuthorityCert.Parsed,
        val idDigestHex: String,
        val skDigestHex: String,
        val downloadFailures: AtomicInteger = AtomicInteger(0),
    )

    private val byIdSk = ConcurrentHashMap<String, Cached>()
    private val denylist = ConcurrentHashMap.newKeySet<String>()
    @Volatile private var waitingForCerts: Boolean = false

    private fun key(id: String, sk: String) = "${id.lowercase()}|${sk.lowercase()}"

    fun put(cert: AuthorityCert.Parsed): Cached {
        val id = cert.identityKeyDigest.joinToString("") { "%02x".format(it) }
        val sk = cert.signingKeyDigest.joinToString("") { "%02x".format(it) }
        val c = Cached(cert, id, sk)
        byIdSk[key(id, sk)] = c
        return c
    }

    /** C Tor `authcert_free_all`. */
    fun authcertFreeAll() {
        byIdSk.clear()
        denylist.clear()
        waitingForCerts = false
    }

    /** C Tor `authority_cert_free_`. */
    fun authorityCertFree_(cert: AuthorityCert.Parsed?): AuthorityCert.Parsed? {
        if (cert == null) return null
        val id = cert.identityKeyDigest.joinToString("") { "%02x".format(it) }
        val sk = cert.signingKeyDigest.joinToString("") { "%02x".format(it) }
        byIdSk.remove(key(id, sk))
        return null
    }

    /** C Tor `authority_cert_get_all`. */
    fun authorityCertGetAll(): List<AuthorityCert.Parsed> =
        byIdSk.values.map { it.cert }

    /** C Tor `authority_cert_get_by_digests`. */
    fun authorityCertGetByDigests(idDigestHex: String, skDigestHex: String): AuthorityCert.Parsed? =
        byIdSk[key(idDigestHex, skDigestHex)]?.cert

    /** C Tor `authority_cert_get_by_sk_digest`. */
    fun authorityCertGetBySkDigest(skDigestHex: String): AuthorityCert.Parsed? {
        val sk = skDigestHex.lowercase()
        return byIdSk.values.firstOrNull { it.skDigestHex == sk }?.cert
    }

    /** C Tor `authority_cert_get_newest_by_id`. */
    fun authorityCertGetNewestById(idDigestHex: String): AuthorityCert.Parsed? {
        val id = idDigestHex.lowercase()
        return byIdSk.values
            .filter { it.idDigestHex == id }
            .maxByOrNull { it.cert.published }
            ?.cert
    }

    /** C Tor `authority_cert_is_denylisted`. */
    fun authorityCertIsDenylisted(skDigestHex: String): Boolean =
        skDigestHex.lowercase() in denylist

    fun authorityCertDenylistAdd(skDigestHex: String) {
        denylist += skDigestHex.lowercase()
    }

    /** C Tor `authority_cert_dl_failed`. */
    fun authorityCertDlFailed(idDigestHex: String, skDigestHex: String = "") {
        val c = byIdSk[key(idDigestHex, skDigestHex)]
        if (c != null) {
            c.downloadFailures.incrementAndGet()
        } else {
            waitingForCerts = true
        }
    }

    /** C Tor `authority_cert_dl_looks_uncertain`. */
    fun authorityCertDlLooksUncertain(idDigestHex: String): Boolean {
        val id = idDigestHex.lowercase()
        val fails = byIdSk.values.filter { it.idDigestHex == id }.sumOf { it.downloadFailures.get() }
        return fails >= 2 || (waitingForCerts && fails >= 1)
    }

    /** C Tor `authority_certs_fetch_missing` — returns ids still missing; thinner stub. */
    fun authorityCertsFetchMissing(wantedIdDigests: List<String>): List<String> {
        waitingForCerts = true
        return wantedIdDigests.filter { id ->
            byIdSk.values.none { it.idDigestHex.equals(id, ignoreCase = true) }
        }
    }

    fun authorityCertsWaiting(): Boolean = waitingForCerts

    fun clearWaiting() {
        waitingForCerts = false
    }
}
