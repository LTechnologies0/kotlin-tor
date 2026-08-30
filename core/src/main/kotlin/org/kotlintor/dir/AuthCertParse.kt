package org.kotlintor.dir

/**
 * Authority certificate parse (C Tor `authcert_parse.c`).
 *
 * Inventory: `L1:feature/dirparse/authcert_parse.c`
 */
object AuthCertParse {
    fun parse(document: String): AuthorityCert.Parsed = AuthorityCert.parse(document)

    fun verify(parsed: AuthorityCert.Parsed): Boolean = AuthorityCert.verify(parsed)

    fun tryParse(document: String): AuthorityCert.Parsed? =
        runCatching { parse(document) }.getOrNull()
}

