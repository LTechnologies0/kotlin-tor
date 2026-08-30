package org.kotlintor.net.dns

/**
 * DNSSEC mode for client resolve / DNSPort (not DNSCrypt).
 * [VALIDATE] = fail-closed local validation over Tor TCP DNS to a recursive.
 */
enum class DnssecMode {
    OFF,
    VALIDATE,
    ;

    companion object {
        fun parse(raw: String): DnssecMode =
            when (raw.trim().lowercase()) {
                "0", "off", "false", "no" -> OFF
                "1", "validate", "true", "yes", "on" -> VALIDATE
                else -> OFF
            }
    }
}

/** RFC 4035 authentication outcomes. */
enum class DnssecStatus {
    SECURE,
    INSECURE,
    BOGUS,
    INDETERMINATE,
}

object DnsTypes {
    const val A = 1
    const val NS = 2
    const val CNAME = 5
    const val SOA = 6
    const val PTR = 12
    const val MX = 15
    const val TXT = 16
    const val AAAA = 28
    const val OPT = 41
    const val DS = 43
    const val RRSIG = 46
    const val NSEC = 47
    const val DNSKEY = 48
    const val NSEC3 = 50
    const val NSEC3PARAM = 51
    const val TLSA = 52
    const val HTTPS = 65
    const val ANY = 255

    const val CLASS_IN = 1

    /** RFC 8624: algorithms we implement. */
    const val ALG_RSASHA256 = 8
    const val ALG_ECDSAP256SHA256 = 13

    fun supportedAlg(alg: Int): Boolean =
        alg == ALG_RSASHA256 || alg == ALG_ECDSAP256SHA256
}
