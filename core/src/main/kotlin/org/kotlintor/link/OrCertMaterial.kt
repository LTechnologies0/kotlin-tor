package org.kotlintor.link

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519KeyPair
import org.kotlintor.hs.Ed25519Cert
import org.kotlintor.util.SecureRandomSource
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Date
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Relay OR identity + link certificates for TLS and CERTS cells
 * (RSA legacy + prop220 Ed25519 IDENTITY_V_SIGNING / SIGNING_V_TLS_CERT).
 * Fingerprint = SHA1(PKCS#1 RSAPublicKey), matching [CertsCell.rsaFingerprint].
 */
class OrCertMaterial(
    val identityKey: KeyPair,
    val linkKey: KeyPair,
    val identityCert: X509Certificate,
    val linkCert: X509Certificate,
) {
    val identityFingerprint: ByteArray = CertsCell.rsaFingerprint(identityCert)

    /**
     * CERTS cell: RSA types 1–2 plus Ed25519 types 4–5 when [edIdentity]/[edSigning] are given.
     */
    fun certsCellPayload(
        edIdentity: Ed25519KeyPair? = null,
        edSigning: Ed25519KeyPair? = null,
    ): ByteArray {
        val idDer = identityCert.encoded
        val linkDer = linkCert.encoded
        val parts = ArrayList<Byte>()
        fun addCert(type: Int, der: ByteArray) {
            parts += type.toByte()
            parts += ((der.size ushr 8) and 0xff).toByte()
            parts += (der.size and 0xff).toByte()
            for (b in der) parts += b
        }
        val edCerts = if (edIdentity != null && edSigning != null) {
            val expHours = Instant.now().epochSecond / 3600 + 24L * 60 // ~60 days
            val idVSigning = Ed25519Cert.encode(
                certType = Ed25519Cert.TYPE_IDENTITY_V_SIGNING,
                certifiedKey = edSigning.publicKey,
                expirationHours = expHours,
                signingKeySeed = edIdentity.privateKey,
                signedWithEd25519 = edIdentity.publicKey,
            )
            val tlsDigest = Digests.sha256(linkDer)
            val signingVTls = Ed25519Cert.encode(
                certType = Ed25519Cert.TYPE_SIGNING_V_TLS_CERT,
                certifiedKey = tlsDigest,
                expirationHours = expHours,
                signingKeySeed = edSigning.privateKey,
                certifiedKeyType = Ed25519Cert.KEY_TYPE_SHA256_OF_X509,
            )
            val rsaIdVIdentity = RsaEdCrossCert.encode(
                ed25519Identity = edIdentity.publicKey,
                rsaIdentityPrivate = identityKey.private,
                expirationHours = expHours,
            )
            listOf(
                Ed25519Cert.TYPE_IDENTITY_V_SIGNING to idVSigning,
                Ed25519Cert.TYPE_SIGNING_V_TLS_CERT to signingVTls,
                RsaEdCrossCert.CERTS_TYPE to rsaIdVIdentity,
            )
        } else {
            emptyList()
        }
        parts += (2 + edCerts.size).toByte()
        addCert(2, idDer) // RSA_ID_X509
        addCert(1, linkDer) // TLS_LINK_X509
        for ((type, der) in edCerts) addCert(type, der)
        return parts.toByteArray()
    }

    /** AUTH_CHALLENGE: 32-byte challenge + method Ed25519-SHA256-RFC5705. */
    fun authChallengePayload(): ByteArray = AuthChallenge.encode()

    fun serverSocketFactory(): SSLServerSocketFactory {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        val pass = "kotlin-tor".toCharArray()
        ks.setKeyEntry("link", linkKey.private, pass, arrayOf(linkCert, identityCert))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, pass)
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, arrayOf(trustAll), java.security.SecureRandom())
        return ctx.serverSocketFactory
    }

    fun persist(dir: Path) {
        Files.createDirectories(dir)
        Files.write(dir.resolve("secret_id_key.pkcs8"), identityKey.private.encoded)
        Files.write(dir.resolve("secret_onion_key_ntor"), ByteArray(0)) // placeholder; onion separate
        Files.write(dir.resolve("secret_link_key.pkcs8"), linkKey.private.encoded)
        Files.write(dir.resolve("identity_cert.der"), identityCert.encoded)
        Files.write(dir.resolve("link_cert.der"), linkCert.encoded)
        Files.write(dir.resolve("fingerprint"), identityFingerprint)
    }

    companion object {
        private val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

        init {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        fun loadOrGenerate(dir: Path): OrCertMaterial {
            Files.createDirectories(dir)
            val idPrivPath = dir.resolve("secret_id_key.pkcs8")
            val linkPrivPath = dir.resolve("secret_link_key.pkcs8")
            val idCertPath = dir.resolve("identity_cert.der")
            val linkCertPath = dir.resolve("link_cert.der")
            if (Files.exists(idPrivPath) && Files.exists(linkPrivPath) &&
                Files.exists(idCertPath) && Files.exists(linkCertPath)
            ) {
                val kf = KeyFactory.getInstance("RSA")
                val idPriv = kf.generatePrivate(PKCS8EncodedKeySpec(Files.readAllBytes(idPrivPath)))
                val linkPriv = kf.generatePrivate(PKCS8EncodedKeySpec(Files.readAllBytes(linkPrivPath)))
                val cf = java.security.cert.CertificateFactory.getInstance("X.509")
                val idCert = cf.generateCertificate(Files.newInputStream(idCertPath)) as X509Certificate
                val linkCert = cf.generateCertificate(Files.newInputStream(linkCertPath)) as X509Certificate
                val idPub = idCert.publicKey
                val linkPub = linkCert.publicKey
                return OrCertMaterial(
                    KeyPair(idPub, idPriv),
                    KeyPair(linkPub, linkPriv),
                    idCert,
                    linkCert,
                )
            }
            return generate().also { it.persist(dir) }
        }

        fun generate(): OrCertMaterial {
            val kpg = KeyPairGenerator.getInstance("RSA")
            kpg.initialize(2048)
            val identity = kpg.generateKeyPair()
            val link = kpg.generateKeyPair()
            val now = System.currentTimeMillis()
            val notBefore = Date(now - 86_400_000L)
            val notAfter = Date(now + 3650L * 86_400_000L)
            val idCert = selfSigned(identity, "CN=kotlin-tor identity", notBefore, notAfter)
            val linkCert = signedBy(
                subjectKey = link,
                issuerKey = identity,
                subjectDn = "CN=kotlin-tor link",
                issuerDn = "CN=kotlin-tor identity",
                notBefore = notBefore,
                notAfter = Date(now + 60L * 86_400_000L),
            )
            return OrCertMaterial(identity, link, idCert, linkCert)
        }

        private fun selfSigned(
            kp: KeyPair,
            dn: String,
            notBefore: Date,
            notAfter: Date,
        ): X509Certificate {
            val name = X500Name(dn)
            val serial = BigInteger(1, SecureRandomSource.nextBytes(16))
            val builder = JcaX509v3CertificateBuilder(name, serial, notBefore, notAfter, name, kp.public)
            val signer = JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(kp.private)
            return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
        }

        private fun signedBy(
            subjectKey: KeyPair,
            issuerKey: KeyPair,
            subjectDn: String,
            issuerDn: String,
            notBefore: Date,
            notAfter: Date,
        ): X509Certificate {
            val serial = BigInteger(1, SecureRandomSource.nextBytes(16))
            val builder = JcaX509v3CertificateBuilder(
                X500Name(issuerDn),
                serial,
                notBefore,
                notAfter,
                X500Name(subjectDn),
                subjectKey.public,
            )
            val signer = JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(issuerKey.private)
            return JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer))
        }
    }
}
