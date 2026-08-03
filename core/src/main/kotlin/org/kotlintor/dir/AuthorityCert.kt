package org.kotlintor.dir

import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.kotlintor.crypto.Digests
import org.kotlintor.util.toHex
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.interfaces.RSAPublicKey as JrsaPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * V3 directory authority certificate (`authority_cert_t` / `authcert_parse.c`).
 *
 * Binds long-term RSA identity key to medium-term signing key. Hash for the
 * certification signature is SHA1 of the document from
 * `dir-key-certificate-version` through the newline before
 * `dir-key-certification` (C Tor `router_get_hash_impl`).
 */
object AuthorityCert {
    private val tsFmt =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)

    data class Parsed(
        val version: Int,
        val fingerprintHex: String,
        val published: String,
        val expires: String,
        val identityPkcs1: ByteArray,
        val signingPkcs1: ByteArray,
        val signingKeyDigest: ByteArray,
        val identityKeyDigest: ByteArray,
        val address: String?,
        val dirPort: Int?,
        val certification: ByteArray,
        val crossCert: ByteArray?,
        val raw: String,
    ) {
        val identityFingerprint: ByteArray get() = Digests.sha1(identityPkcs1)
    }

    data class Material(
        val identity: KeyPair,
        val signing: KeyPair,
    ) {
        val identityFingerprint: ByteArray = rsaPkcs1Digest(identity.public as JrsaPublicKey)
        val signingKeyDigest: ByteArray = rsaPkcs1Digest(signing.public as JrsaPublicKey)

        fun formatCertificate(
            published: Instant = Instant.now(),
            expires: Instant = published.plusSeconds(90L * 24 * 3600),
            address: String? = null,
            dirPort: Int? = null,
        ): String {
            val idPem = encodeRsaPublicPem(identity.public as JrsaPublicKey)
            val sigPem = encodeRsaPublicPem(signing.public as JrsaPublicKey)
            val body = buildString {
                appendLine("dir-key-certificate-version 3")
                appendLine("fingerprint ${identityFingerprint.toHex().uppercase()}")
                if (address != null && dirPort != null) {
                    appendLine("dir-address $address:$dirPort")
                }
                appendLine("dir-key-published ${tsFmt.format(published)}")
                appendLine("dir-key-expires ${tsFmt.format(expires)}")
                appendLine("dir-identity-key")
                append(idPem)
                if (!idPem.endsWith("\n")) appendLine()
                appendLine("dir-signing-key")
                append(sigPem)
                if (!sigPem.endsWith("\n")) appendLine()
                appendLine("dir-key-crosscert")
                append(encodeCrossCert(identityFingerprint, signing))
                appendLine("dir-key-certification")
            }
            val region = signedRegion(body).toByteArray(Charsets.US_ASCII)
            val sig = Signature.getInstance("SHA1withRSA").apply {
                initSign(identity.private)
                update(region)
            }.sign()
            return body + pemBlock("SIGNATURE", sig)
        }
    }

    fun generate(bits: Int = 2048): Material {
        ensureBc()
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(bits)
        return Material(identity = kpg.generateKeyPair(), signing = kpg.generateKeyPair())
    }

    fun parse(text: String): Parsed {
        val version = lineValue(text, "dir-key-certificate-version")?.toIntOrNull()
            ?: error("missing dir-key-certificate-version")
        require(version == 3) { "unsupported cert version $version" }
        val fp = lineValue(text, "fingerprint")?.replace(" ", "")
            ?: error("missing fingerprint")
        val published = lineValue(text, "dir-key-published") ?: error("missing published")
        val expires = lineValue(text, "dir-key-expires") ?: error("missing expires")
        val addrLine = lineValue(text, "dir-address")
        val address: String?
        val dirPort: Int?
        if (addrLine != null && ':' in addrLine) {
            val i = addrLine.lastIndexOf(':')
            address = addrLine.substring(0, i)
            dirPort = addrLine.substring(i + 1).toIntOrNull()
        } else {
            address = null
            dirPort = null
        }
        val identityPkcs1 = decodeRsaPublicPem(extractPem(text, "RSA PUBLIC KEY", after = "dir-identity-key"))
        val signingPkcs1 = decodeRsaPublicPem(extractPem(text, "RSA PUBLIC KEY", after = "dir-signing-key"))
        val cross = runCatching { decodePem(extractPem(text, "CROSSCERT")) }.getOrNull()
        val certification = decodePem(extractPem(text, "SIGNATURE", after = "dir-key-certification"))
        return Parsed(
            version = version,
            fingerprintHex = fp.uppercase(),
            published = published,
            expires = expires,
            identityPkcs1 = identityPkcs1,
            signingPkcs1 = signingPkcs1,
            signingKeyDigest = Digests.sha1(signingPkcs1),
            identityKeyDigest = Digests.sha1(identityPkcs1),
            address = address,
            dirPort = dirPort,
            certification = certification,
            crossCert = cross,
            raw = text,
        )
    }

    fun verify(parsed: Parsed): Boolean {
        if (!parsed.identityFingerprint.contentEquals(
                parsed.fingerprintHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
            )
        ) {
            return false
        }
        if (!parsed.identityKeyDigest.contentEquals(parsed.identityFingerprint)) return false
        val region = signedRegion(parsed.raw).toByteArray(Charsets.US_ASCII)
        val pub = KeyFactory.getInstance("RSA").generatePublic(
            X509EncodedKeySpec(pkcs1ToSpki(parsed.identityPkcs1)),
        )
        return Signature.getInstance("SHA1withRSA").run {
            initVerify(pub)
            update(region)
            verify(parsed.certification)
        }
    }

    /** SHA1(PKCS#1 RSAPublicKey) — matches `crypto_pk_get_digest`. */
    fun rsaPkcs1Digest(pub: JrsaPublicKey): ByteArray {
        val spki = SubjectPublicKeyInfo.getInstance(pub.encoded)
        return Digests.sha1(spki.publicKeyData.bytes)
    }

    private fun signedRegion(doc: String): String {
        val marker = "\ndir-key-certification"
        val idx = doc.indexOf(marker)
        require(idx >= 0) { "no dir-key-certification" }
        // Include leading content through the newline before the keyword line.
        return doc.substring(0, idx + 1)
    }

    private fun lineValue(text: String, key: String): String? {
        val prefix = "$key "
        return text.lineSequence().firstOrNull { it.startsWith(prefix) }
            ?.removePrefix(prefix)?.trim()
    }

    private fun extractPem(text: String, label: String, after: String? = null): String {
        val begin = "-----BEGIN $label-----"
        val end = "-----END $label-----"
        val from = if (after != null) {
            val a = text.indexOf(after)
            require(a >= 0) { "missing $after" }
            text.indexOf(begin, a)
        } else {
            text.indexOf(begin)
        }
        require(from >= 0) { "missing $begin" }
        val to = text.indexOf(end, from)
        require(to >= 0) { "missing $end" }
        return text.substring(from, to + end.length)
    }

    private fun decodePem(block: String): ByteArray {
        val lines = block.lineSequence()
            .filter { !it.startsWith("-----") && it.isNotBlank() }
            .joinToString("")
        return Base64.getDecoder().decode(lines)
    }

    private fun decodeRsaPublicPem(block: String): ByteArray = decodePem(block)

    private fun encodeRsaPublicPem(pub: JrsaPublicKey): String {
        val spki = SubjectPublicKeyInfo.getInstance(pub.encoded)
        val pkcs1 = spki.publicKeyData.bytes
        return pemBlock("RSA PUBLIC KEY", pkcs1)
    }

    private fun encodeCrossCert(identityFp: ByteArray, signing: KeyPair): String {
        // Compact: RSA-SHA1(identity fingerprint) by signing key (dir-spec crosscert).
        val sig = Signature.getInstance("SHA1withRSA").apply {
            initSign(signing.private)
            update(identityFp)
        }.sign()
        return pemBlock("CROSSCERT", sig)
    }

    private fun pemBlock(label: String, der: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(der)
        return buildString {
            appendLine("-----BEGIN $label-----")
            b64.chunked(64).forEach { appendLine(it) }
            appendLine("-----END $label-----")
        }
    }

    private fun pkcs1ToSpki(pkcs1: ByteArray): ByteArray {
        val rsa = RSAPublicKey.getInstance(pkcs1)
        return SubjectPublicKeyInfo(
            org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption,
                org.bouncycastle.asn1.DERNull.INSTANCE,
            ),
            rsa,
        ).encoded
    }

    private fun ensureBc() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /** Persist PKCS8 keys for TestingTorNetwork dirauth. */
    fun persist(material: Material, dir: java.nio.file.Path, certificate: String = material.formatCertificate()) {
        java.nio.file.Files.createDirectories(dir)
        java.nio.file.Files.write(dir.resolve("authority_identity_key.pkcs8"), material.identity.private.encoded)
        java.nio.file.Files.write(dir.resolve("authority_signing_key.pkcs8"), material.signing.private.encoded)
        java.nio.file.Files.write(dir.resolve("authority_certificate"), certificate.toByteArray(Charsets.US_ASCII))
    }

    fun loadMaterial(dir: java.nio.file.Path): Material? {
        val idPath = dir.resolve("authority_identity_key.pkcs8")
        val sigPath = dir.resolve("authority_signing_key.pkcs8")
        val certPath = dir.resolve("authority_certificate")
        if (!java.nio.file.Files.isRegularFile(idPath) ||
            !java.nio.file.Files.isRegularFile(sigPath) ||
            !java.nio.file.Files.isRegularFile(certPath)
        ) {
            return null
        }
        ensureBc()
        val kf = KeyFactory.getInstance("RSA")
        val parsed = parse(java.nio.file.Files.readString(certPath))
        val idPub = kf.generatePublic(X509EncodedKeySpec(pkcs1ToSpki(parsed.identityPkcs1)))
        val sigPub = kf.generatePublic(X509EncodedKeySpec(pkcs1ToSpki(parsed.signingPkcs1)))
        val idPriv = kf.generatePrivate(PKCS8EncodedKeySpec(java.nio.file.Files.readAllBytes(idPath)))
        val sigPriv = kf.generatePrivate(PKCS8EncodedKeySpec(java.nio.file.Files.readAllBytes(sigPath)))
        return Material(
            identity = KeyPair(idPub, idPriv),
            signing = KeyPair(sigPub, sigPriv),
        )
    }
}
