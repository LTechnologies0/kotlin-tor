package org.kotlintor.or

/** C Tor `vote_microdesc_hash_t`. */
data class VoteMicrodescHash(
    val method: Int,
    val digestHex: String,
)
