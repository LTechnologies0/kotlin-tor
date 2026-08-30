package org.kotlintor.relay

import org.kotlintor.dir.SigCommon
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * Build a minimal server descriptor document for a kotlin-tor relay
 * ([dir-spec server descriptor](https://spec.torproject.org/dir-spec/server-descriptor-format.html)).
 *
 * Without real RSA onion/signing keys and Ed25519 cert PEM this body is not
 * authority-publishable; digests still follow C Tor `router_get_router_hash`.
 */
object RelayDescriptorBuilder {
    private val tsFmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)

    data class Input(
        val nickname: String,
        val address: String,
        val orPort: Int,
        val dirPort: Int,
        val identityFingerprintHex: String,
        val ntorOnionKey: ByteArray,
        val ed25519Identity: ByteArray?,
        /** Full PEM body of an `ED25519 CERT` (no BEGIN/END lines). Null → omit identity-ed25519. */
        val identityEd25519CertBody: String? = null,
        /** RSA onion-key PEM body (no BEGIN/END). Null → omit onion-key section. */
        val onionKeyPemBody: String? = null,
        /** RSA signing-key PEM body (no BEGIN/END). Null → omit signing-key section. */
        val signingKeyPemBody: String? = null,
        val bandwidth: Long = 1000,
        val family: List<String> = emptyList(),
        val exitPolicyLines: List<String> = listOf("reject *:*"),
        val contact: String = "kotlin-tor@localhost",
        val platform: String = "Tor 0.1.0-kotlin on Linux",
        /** Base64 router-sig-ed25519 argument; null omits the line. */
        val routerSigEd25519B64: String? = null,
    )

    fun build(input: Input, published: Instant = Instant.now()): String {
        val fpSpaced = input.identityFingerprintHex.chunked(4).joinToString(" ")
        val ntorB64 = Base64.getEncoder().withoutPadding().encodeToString(input.ntorOnionKey)
        val edB64 = input.ed25519Identity?.let {
            Base64.getEncoder().withoutPadding().encodeToString(it)
        }
        return buildString {
            append("router ${input.nickname} ${input.address} ${input.orPort} 0 ${input.dirPort}\n")
            if (edB64 != null && input.identityEd25519CertBody != null) {
                append("identity-ed25519\n")
                append("-----BEGIN ED25519 CERT-----\n")
                append(input.identityEd25519CertBody.trim())
                append("\n-----END ED25519 CERT-----\n")
            }
            if (edB64 != null) {
                append("master-key-ed25519 $edB64\n")
            }
            append("platform ${input.platform}\n")
            append("proto Link=4,5 FlowCtrl=1,2 Relay=1-6\n")
            append("published ${tsFmt.format(published)}\n")
            append("fingerprint $fpSpaced\n")
            append("uptime 1\n")
            append("bandwidth ${input.bandwidth} ${input.bandwidth} ${input.bandwidth}\n")
            if (input.onionKeyPemBody != null) {
                append("onion-key\n-----BEGIN RSA PUBLIC KEY-----\n")
                append(input.onionKeyPemBody.trim())
                append("\n-----END RSA PUBLIC KEY-----\n")
            }
            if (input.signingKeyPemBody != null) {
                append("signing-key\n-----BEGIN RSA PUBLIC KEY-----\n")
                append(input.signingKeyPemBody.trim())
                append("\n-----END RSA PUBLIC KEY-----\n")
            }
            append("ntor-onion-key $ntorB64\n")
            if (input.family.isNotEmpty()) {
                append("family ${input.family.joinToString(" ")}\n")
            }
            for (line in input.exitPolicyLines) append("$line\n")
            // dir-spec: contact before signatures; omit empty sig lines
            append("contact ${input.contact}\n")
            if (input.routerSigEd25519B64 != null) {
                append("router-sig-ed25519 ${input.routerSigEd25519B64}\n")
            }
            append("router-signature\n")
        }
    }

    /**
     * C Tor `router_get_router_hash` — SHA-1 of region from line-start `router `
     * through the newline that terminates the `router-signature` keyword line
     * (excludes the PEM signature object that follows).
     */
    fun digestSha1Hex(document: String): String {
        val dig = SigCommon.getHashImpl(
            document,
            startStr = "router ",
            endStr = "\nrouter-signature",
            endC = '\n',
            alg = SigCommon.DigestAlg.SHA1,
        ) ?: error("descriptor missing router / router-signature region for digest")
        return dig.joinToString("") { "%02x".format(it) }
    }
}
