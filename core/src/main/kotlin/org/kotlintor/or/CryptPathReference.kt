package org.kotlintor.or

/** C Tor `crypt_path_reference_t`. */
data class CryptPathReference(
    val hopIndex: Int,
    val circuitId: Long,
)
