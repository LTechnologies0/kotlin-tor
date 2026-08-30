package org.kotlintor.or

/** C Tor `signed_descriptor_t`. */
data class SignedDescriptor(
    val body: String,
    val identityHex: String,
    val publishedMs: Long = 0,
)
