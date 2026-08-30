package org.kotlintor.or

/** C Tor `or_handshake_certs_t`. */
data class OrHandshakeCerts(
    val idCert: ByteArray? = null,
    val authCert: ByteArray? = null,
    val linkCert: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is OrHandshakeCerts &&
            idCert.contentEq(other.idCert) &&
            authCert.contentEq(other.authCert) &&
            linkCert.contentEq(other.linkCert)
    override fun hashCode(): Int =
        (idCert?.contentHashCode() ?: 0) xor (authCert?.contentHashCode() ?: 0) xor
            (linkCert?.contentHashCode() ?: 0)
}

private fun ByteArray?.contentEq(other: ByteArray?): Boolean =
    when {
        this == null && other == null -> true
        this == null || other == null -> false
        else -> contentEquals(other)
    }
