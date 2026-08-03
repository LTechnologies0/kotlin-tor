package org.kotlintor.relay

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64

/**
 * Build a minimal server descriptor document for a kotlin-tor relay (dir-spec lite).
 * Signing / DirAuth publish still require authority acceptance; this produces the body.
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
        val bandwidth: Long = 1000,
        val family: List<String> = emptyList(),
        val exitPolicyLines: List<String> = listOf("reject *:*"),
        val contact: String = "kotlin-tor@localhost",
        val platform: String = "Tor 0.1.0-kotlin on Linux",
    )

    fun build(input: Input, published: Instant = Instant.now()): String {
        val fpSpaced = input.identityFingerprintHex.chunked(4).joinToString(" ")
        val ntorB64 = Base64.getEncoder().withoutPadding().encodeToString(input.ntorOnionKey)
        val edB64 = input.ed25519Identity?.let {
            Base64.getEncoder().withoutPadding().encodeToString(it)
        }
        return buildString {
            append("router ${input.nickname} ${input.address} ${input.orPort} 0 ${input.dirPort}\n")
            append("identity-ed25519\n")
            if (edB64 != null) {
                append("-----BEGIN ED25519 CERT-----\n")
                append("(see CERTS cell; master-key-ed25519 $edB64)\n")
                append("-----END ED25519 CERT-----\n")
                append("master-key-ed25519 $edB64\n")
            }
            append("platform ${input.platform}\n")
            append("proto Link=4,5 FlowCtrl=1,2 Relay=1-6\n")
            append("published ${tsFmt.format(published)}\n")
            append("fingerprint $fpSpaced\n")
            append("uptime 1\n")
            append("bandwidth ${input.bandwidth} ${input.bandwidth} ${input.bandwidth}\n")
            append("onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END RSA PUBLIC KEY-----\n")
            append("signing-key\n-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END RSA PUBLIC KEY-----\n")
            append("ntor-onion-key $ntorB64\n")
            if (input.family.isNotEmpty()) {
                append("family ${input.family.joinToString(" ")}\n")
            }
            for (line in input.exitPolicyLines) append("$line\n")
            append("router-sig-ed25519\n")
            append("router-signature\n")
            append("contact ${input.contact}\n")
        }
    }

    fun digestSha1Hex(document: String): String =
        java.security.MessageDigest.getInstance("SHA-1")
            .digest(document.toByteArray())
            .joinToString("") { "%02x".format(it) }
}
