package org.kotlintor.hs

import org.kotlintor.crypto.AesCtr
import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519Blind
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.crypto.Shake256
import org.kotlintor.crypto.X25519KeyPair
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat
import org.kotlintor.util.u64be
import java.util.Base64

/**
 * Onion service v3 descriptor parse / decrypt / encrypt (rend-spec HS-DESC).
 */
data class HsDescriptorOuter(
    val lifetimeHours: Int,
    val signingKeyCertPem: String,
    val revisionCounter: Long,
    val superencrypted: ByteArray,
    val signatureB64: String?,
    val raw: String,
)

data class IntroductionPoint(
    /** Packed nspec + link-specifier list from the introduction-point line. */
    val linkSpecifiers: ByteArray,
    /** Intro-point relay onion key (CREATE/EXTEND to the IP). */
    val onionKeyNtor: ByteArray,
    /** KP_hss_ntor — service encryption key for INTRODUCE1 (enc-key ntor). */
    val encKeyNtor: ByteArray,
    val authKeyCertPem: String?,
    val encKeyCertPem: String?,
) {
    val authKey: ByteArray
        get() = Ed25519Cert.certifiedKeyFromPem(
            authKeyCertPem ?: error("introduction point missing auth-key cert"),
        )
}

data class HsDescriptorInner(
    val create2Formats: List<Int>,
    val introductionPoints: List<IntroductionPoint>,
    val singleOnion: Boolean,
    val raw: String,
)

data class HsDescriptorBuildInput(
    val publicIdentity: ByteArray,
    val privateIdentitySeed: ByteArray,
    val period: HsTimePeriod,
    val revisionCounter: Long,
    val lifetimeMinutes: Int = 180,
    val introPoints: List<IntroPointDescriptor>,
    val create2Formats: List<Int> = listOf(2),
    /** Optional prop327 PoW challenge for inner layer. */
    val powChallenge: HsPow.Challenge? = null,
    /** Authorized client credentials (x25519 client-auth); empty = open. */
    val authorizedClients: List<HsClientAuth.ClientCred> = emptyList(),
)

data class IntroPointDescriptor(
    val linkSpecifiers: ByteArray,
    val onionKeyNtor: ByteArray,
    val authPublic: ByteArray,
    val encKey: X25519KeyPair,
)

object HsDescriptorCodec {
    private const val SALT_LEN = 16
    private const val KEY_LEN = 32
    private const val IV_LEN = 16
    private const val MAC_LEN = 32
    private const val PAD_BLOCK = 10_000
    private val SIG_PREFIX = "Tor onion service descriptor sig v3".toByteArray()

    fun parseOuter(document: String): HsDescriptorOuter {
        var lifetime = 180
        var revision = 0L
        var cert = ""
        var sig: String? = null
        val superEnc = extractPemObject(document, "superencrypted")
            ?: error("missing superencrypted object")
        var inCert = false
        val certBuf = StringBuilder()
        for (line in document.lineSequence()) {
            when {
                line.startsWith("descriptor-lifetime ") ->
                    lifetime = line.removePrefix("descriptor-lifetime ").trim().toInt()
                line.startsWith("revision-counter ") ->
                    revision = line.removePrefix("revision-counter ").trim().toLong()
                line.startsWith("descriptor-signing-key-cert") -> inCert = true
                inCert && line.startsWith("-----BEGIN") -> {
                    certBuf.appendLine(line)
                }
                inCert && line.startsWith("-----END") -> {
                    certBuf.appendLine(line)
                    cert = certBuf.toString()
                    inCert = false
                }
                inCert -> certBuf.appendLine(line)
                line.startsWith("signature ") ->
                    sig = line.removePrefix("signature ").trim()
            }
        }
        return HsDescriptorOuter(lifetime, cert, revision, superEnc, sig, document)
    }

    fun decrypt(
        outer: HsDescriptorOuter,
        publicIdentity: ByteArray,
        blindedPublic: ByteArray,
        descriptorCookie: ByteArray = ByteArray(0),
    ): HsDescriptorInner {
        val subcred = HsKeyBlind.subcredential(publicIdentity, blindedPublic)
        val firstPlain = decryptLayer(
            blob = outer.superencrypted,
            secretData = blindedPublic,
            subcredential = subcred,
            revision = outer.revisionCounter,
            stringConstant = "hsdir-superencrypted-data",
        )
        val encryptedObj = extractPemObject(firstPlain.decodeToString().trimEnd('\u0000'), "encrypted")
            ?: error("missing encrypted object in first layer")
        val secondPlain = decryptLayer(
            blob = encryptedObj,
            secretData = concat(blindedPublic, descriptorCookie),
            subcredential = subcred,
            revision = outer.revisionCounter,
            stringConstant = "hsdir-encrypted-data",
        )
        val text = secondPlain.decodeToString().trimEnd('\u0000')
        return parseInner(text)
    }

    /**
     * Decrypt with client authorization: recover descriptor cookie via ECDH with
     * desc-auth-ephemeral-key, then decrypt the inner layer.
     */
    fun decryptWithClientAuth(
        outer: HsDescriptorOuter,
        publicIdentity: ByteArray,
        blindedPublic: ByteArray,
        client: HsClientAuth.ClientCred,
    ): HsDescriptorInner {
        val subcred = HsKeyBlind.subcredential(publicIdentity, blindedPublic)
        val firstPlainBytes = decryptLayer(
            blob = outer.superencrypted,
            secretData = blindedPublic,
            subcredential = subcred,
            revision = outer.revisionCounter,
            stringConstant = "hsdir-superencrypted-data",
        )
        val firstText = firstPlainBytes.decodeToString().trimEnd('\u0000')
        val (ephemeral, entries) = HsClientAuth.parseAuthClients(firstText)
        require(ephemeral != null) { "missing desc-auth-ephemeral-key" }
        val wantId = HsClientAuth.clientId(client.publicKey)
        val entry = entries.firstOrNull { it.clientId.contentEquals(wantId) }
            ?: error("no auth-client entry for this client")
        val cookie = HsClientAuth.openCookie(client.privateKey, ephemeral, entry.encryptedCookie)
        return decrypt(outer, publicIdentity, blindedPublic, cookie)
    }

    /** Build a signed outer HS descriptor document (no client auth). */
    fun build(input: HsDescriptorBuildInput): String {
        val blinded = HsKeyBlind.blindSecretKey(
            input.privateIdentitySeed,
            input.publicIdentity,
            input.period,
        )
        val blindedPublic = blinded.publicKey
        val subcred = HsKeyBlind.subcredential(input.publicIdentity, blindedPublic)
        val signing = Ed25519Keys.generate()
        val expHours = (System.currentTimeMillis() / 3_600_000L) + 24
        val signingCert = Ed25519Cert.encode(
            certType = Ed25519Cert.TYPE_BLINDED_ID_V_SIGNING,
            certifiedKey = signing.publicKey,
            expirationHours = expHours,
            signingExpanded = blinded,
            signedWithEd25519 = blindedPublic,
        )
        val signingCertPem = Ed25519Cert.toPem(signingCert)

        val innerText = buildInnerPlaintext(input, signing.privateKey, expHours)
        val cookie = if (input.authorizedClients.isNotEmpty()) {
            SecureRandomSource.nextBytes(16)
        } else {
            ByteArray(0)
        }
        val innerBlob = encryptLayer(
            plaintext = padTo10k(innerText.toByteArray()),
            secretData = concat(blindedPublic, cookie),
            subcredential = subcred,
            revision = input.revisionCounter,
            stringConstant = "hsdir-encrypted-data",
        )
        val firstPlain = buildFirstLayerPlaintext(innerBlob, input.authorizedClients, cookie)
        val superEnc = encryptLayer(
            plaintext = padTo10k(firstPlain.toByteArray()),
            secretData = blindedPublic,
            subcredential = subcred,
            revision = input.revisionCounter,
            stringConstant = "hsdir-superencrypted-data",
        )

        val body = buildString {
            append("hs-descriptor 3\n")
            append("descriptor-lifetime ${input.lifetimeMinutes}\n")
            append("descriptor-signing-key-cert\n")
            append(signingCertPem)
            if (!signingCertPem.endsWith("\n")) append('\n')
            append("revision-counter ${input.revisionCounter}\n")
            append("superencrypted\n")
            append(pemMessage(superEnc))
            // Superencrypted object itself has no trailing newline (rend-spec), but the
            // signed region includes the newline that terminates that section before
            // the "signature" line.
            append('\n')
        }
        val toSign = concat(SIG_PREFIX, body.toByteArray())
        val sig = Ed25519Keys.sign(signing.privateKey, toSign)
        val sigB64 = Base64.getEncoder().withoutPadding().encodeToString(sig)
        return body + "signature $sigB64\n"
    }

    private fun buildInnerPlaintext(
        input: HsDescriptorBuildInput,
        signingSeed: ByteArray,
        expHours: Long,
    ): String = buildString {
        append("create2-formats")
        for (f in input.create2Formats) append(' ').append(f)
        append('\n')
        input.powChallenge?.let { ch ->
            val exp = System.currentTimeMillis() / 1000L + 3600
            append(HsPow.powParamsLine(ch, exp))
            append('\n')
        }
        for (ip in input.introPoints) {
            append("introduction-point ")
            append(Base64.getEncoder().withoutPadding().encodeToString(ip.linkSpecifiers))
            append('\n')
            append("onion-key ntor ")
            append(Base64.getEncoder().withoutPadding().encodeToString(ip.onionKeyNtor))
            append('\n')
            val authCert = Ed25519Cert.encode(
                certType = Ed25519Cert.TYPE_HS_IP_V_SIGNING,
                certifiedKey = ip.authPublic,
                expirationHours = expHours,
                signingKeySeed = signingSeed,
            )
            append("auth-key\n")
            append(Ed25519Cert.toPem(authCert))
            append('\n')
            append("enc-key ntor ")
            append(Base64.getEncoder().withoutPadding().encodeToString(ip.encKey.publicKey))
            append('\n')
            val encCert = Ed25519Cert.encode(
                certType = Ed25519Cert.TYPE_HS_IP_CC_SIGNING,
                certifiedKey = ip.encKey.publicKey,
                expirationHours = expHours,
                signingKeySeed = signingSeed,
            )
            append("enc-key-cert\n")
            append(Ed25519Cert.toPem(encCert))
            append('\n')
        }
    }

    private fun buildFirstLayerPlaintext(
        encryptedBlob: ByteArray,
        authorizedClients: List<HsClientAuth.ClientCred> = emptyList(),
        descriptorCookie: ByteArray = ByteArray(0),
    ): String {
        val ephemeral = org.kotlintor.crypto.Curve25519.generateKeyPair()
        val authClients = if (authorizedClients.isNotEmpty()) {
            require(descriptorCookie.size == 16)
            authorizedClients.joinToString("\n") { cred ->
                val (_, enc) = HsClientAuth.sealCookie(ephemeral.privateKey, cred.publicKey, descriptorCookie)
                HsClientAuth.authClientLine(cred, enc)
            }
        } else {
            (0 until 16).joinToString("\n") {
                val clientId = SecureRandomSource.nextBytes(8)
                val iv = SecureRandomSource.nextBytes(16)
                val cookie = SecureRandomSource.nextBytes(16)
                "auth-client " +
                    Base64.getEncoder().withoutPadding().encodeToString(clientId) + " " +
                    Base64.getEncoder().withoutPadding().encodeToString(iv) + " " +
                    Base64.getEncoder().withoutPadding().encodeToString(cookie)
            }
        }
        // No final newline (C Tor compatibility note in rend-spec).
        return "desc-auth-type x25519\n" +
            "desc-auth-ephemeral-key " +
            Base64.getEncoder().withoutPadding().encodeToString(ephemeral.publicKey) + "\n" +
            authClients + "\n" +
            "encrypted\n" +
            pemMessage(encryptedBlob)
    }

    private fun encryptLayer(
        plaintext: ByteArray,
        secretData: ByteArray,
        subcredential: ByteArray,
        revision: Long,
        stringConstant: String,
    ): ByteArray {
        val salt = SecureRandomSource.nextBytes(SALT_LEN)
        val secretInput = concat(secretData, subcredential, u64be(revision))
        val keys = Shake256.xof(
            concat(secretInput, salt, stringConstant.toByteArray()),
            KEY_LEN + IV_LEN + MAC_LEN,
        )
        val secretKey = keys.copyOfRange(0, KEY_LEN)
        val secretIv = keys.copyOfRange(KEY_LEN, KEY_LEN + IV_LEN)
        val macKey = keys.copyOfRange(KEY_LEN + IV_LEN, KEY_LEN + IV_LEN + MAC_LEN)
        val ciphertext = AesCtr(secretKey, secretIv).process(plaintext)
        val mac = Digests.sha3_256(
            concat(
                u64be(MAC_LEN.toLong()),
                macKey,
                u64be(SALT_LEN.toLong()),
                salt,
                ciphertext,
            ),
        )
        return concat(salt, ciphertext, mac)
    }

    private fun decryptLayer(
        blob: ByteArray,
        secretData: ByteArray,
        subcredential: ByteArray,
        revision: Long,
        stringConstant: String,
    ): ByteArray {
        require(blob.size > SALT_LEN + MAC_LEN) { "encrypted blob too short: ${blob.size}" }
        val salt = blob.copyOfRange(0, SALT_LEN)
        val mac = blob.copyOfRange(blob.size - MAC_LEN, blob.size)
        val ciphertext = blob.copyOfRange(SALT_LEN, blob.size - MAC_LEN)

        val secretInput = concat(secretData, subcredential, u64be(revision))
        val keys = Shake256.xof(
            concat(secretInput, salt, stringConstant.toByteArray()),
            KEY_LEN + IV_LEN + MAC_LEN,
        )
        val secretKey = keys.copyOfRange(0, KEY_LEN)
        val secretIv = keys.copyOfRange(KEY_LEN, KEY_LEN + IV_LEN)
        val macKey = keys.copyOfRange(KEY_LEN + IV_LEN, KEY_LEN + IV_LEN + MAC_LEN)

        val expectMac = Digests.sha3_256(
            concat(
                u64be(MAC_LEN.toLong()),
                macKey,
                u64be(SALT_LEN.toLong()),
                salt,
                ciphertext,
            ),
        )
        check(expectMac.contentEquals(mac)) { "HS descriptor MAC mismatch" }

        return AesCtr(secretKey, secretIv).process(ciphertext)
    }

    private fun parseInner(text: String): HsDescriptorInner {
        val formats = mutableListOf<Int>()
        val intros = mutableListOf<IntroductionPoint>()
        var singleOnion = false
        var curLinks: ByteArray? = null
        var curOnion: ByteArray? = null
        var curEncKey: ByteArray? = null
        var curAuth: String? = null
        var curEncCert: String? = null
        var inAuthCert = false
        var inEncCert = false
        val authBuf = StringBuilder()
        val encBuf = StringBuilder()

        fun flushIntro() {
            val links = curLinks ?: return
            val onion = curOnion ?: return
            val enc = curEncKey ?: onion
            intros += IntroductionPoint(links, onion, enc, curAuth, curEncCert)
            curLinks = null
            curOnion = null
            curEncKey = null
            curAuth = null
            curEncCert = null
        }

        for (line in text.lineSequence()) {
            when {
                line.startsWith("create2-formats ") -> {
                    formats += line.removePrefix("create2-formats ").trim()
                        .split(' ').mapNotNull { it.toIntOrNull() }
                }
                line.trim() == "single-onion-service" -> singleOnion = true
                line.startsWith("introduction-point ") -> {
                    flushIntro()
                    val b64 = line.removePrefix("introduction-point ").trim()
                    curLinks = base64Decode(b64)
                }
                line.startsWith("onion-key ntor ") -> {
                    curOnion = base64Decode(line.substringAfter("ntor ").trim())
                }
                line.startsWith("enc-key ntor ") -> {
                    curEncKey = base64Decode(line.substringAfter("ntor ").trim())
                }
                line.startsWith("auth-key") -> {
                    inAuthCert = true
                    authBuf.clear()
                }
                inAuthCert && line.startsWith("-----BEGIN") -> authBuf.appendLine(line)
                inAuthCert && line.startsWith("-----END") -> {
                    authBuf.appendLine(line)
                    curAuth = authBuf.toString()
                    inAuthCert = false
                }
                inAuthCert -> authBuf.appendLine(line)
                line.startsWith("enc-key-cert") -> {
                    inEncCert = true
                    encBuf.clear()
                }
                inEncCert && line.startsWith("-----BEGIN") -> encBuf.appendLine(line)
                inEncCert && line.startsWith("-----END") -> {
                    encBuf.appendLine(line)
                    curEncCert = encBuf.toString()
                    inEncCert = false
                }
                inEncCert -> encBuf.appendLine(line)
            }
        }
        flushIntro()
        return HsDescriptorInner(formats, intros, singleOnion, text)
    }

    private fun padTo10k(data: ByteArray): ByteArray {
        if (data.isEmpty()) return ByteArray(PAD_BLOCK)
        val rem = data.size % PAD_BLOCK
        if (rem == 0) return data
        return data.copyOf(data.size + (PAD_BLOCK - rem))
    }

    private fun pemMessage(blob: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(blob)
        val lines = b64.chunked(64).joinToString("\n")
        return "-----BEGIN MESSAGE-----\n$lines\n-----END MESSAGE-----"
    }

    private fun extractPemObject(document: String, keyword: String): ByteArray? {
        val lines = document.lineSequence().toList()
        var i = 0
        while (i < lines.size) {
            if (lines[i].trim() == keyword || lines[i].startsWith("$keyword ")) {
                var j = i + 1
                while (j < lines.size && !lines[j].contains("BEGIN MESSAGE")) j++
                if (j >= lines.size) return null
                j++
                val b64 = StringBuilder()
                while (j < lines.size && !lines[j].contains("END MESSAGE")) {
                    b64.append(lines[j].trim())
                    j++
                }
                return base64Decode(b64.toString())
            }
            i++
        }
        return null
    }

    private fun base64Decode(s: String): ByteArray {
        var b64 = s.replace("\\s".toRegex(), "")
        while (b64.length % 4 != 0) b64 += "="
        return Base64.getDecoder().decode(b64)
    }
}
