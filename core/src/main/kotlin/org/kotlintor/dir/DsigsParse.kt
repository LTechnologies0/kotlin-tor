package org.kotlintor.dir

/**
 * Detached consensus signature parse/format (C Tor `dsigs_parse.c`).
 *
 * Inventory: `L1:feature/dirauth/dsigs_parse.c`
 *
 * Implementation: [DetachedSignatures].
 */
object DsigsParse {
    fun digestHex(body: String): String = DetachedSignatures.digestHex(body)

    fun parse(text: String): DetachedSignatures.Detached = DetachedSignatures.parse(text)

    fun formatDetached(
        body: String,
        validAfter: String,
        freshUntil: String,
        validUntil: String,
        signatures: List<DetachedSignatures.DocumentSignature>,
        flavor: String = "ns",
    ): String = DetachedSignatures.formatDetached(
        body, validAfter, freshUntil, validUntil, signatures, flavor,
    )

    /** C Tor `networkstatus_parse_detached_signatures`. */
    fun networkstatusParseDetachedSignatures(text: String): DetachedSignatures.Detached =
        parse(text)

    /** C Tor `ns_detached_signatures_free_`. */
    fun nsDetachedSignaturesFree_(detached: DetachedSignatures.Detached?): DetachedSignatures.Detached? =
        null
}
