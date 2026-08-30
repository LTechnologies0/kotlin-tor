package org.kotlintor.dir

/**
 * Router descriptor parse (C Tor `routerparse.c`).
 *
 * Inventory: `L1:feature/dirparse/routerparse.c`
 *
 * Implementation: [DescriptorParser].
 */
object RouterParse {
    fun parse(document: String, fallbackFingerprintHex: String? = null) =
        DescriptorParser.parse(document, fallbackFingerprintHex)
}
