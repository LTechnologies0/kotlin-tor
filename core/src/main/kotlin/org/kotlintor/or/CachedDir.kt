package org.kotlintor.or

/** C Tor `cached_dir_t`. */
data class CachedDir(
    val dir: String,
    val publishedMs: Long = System.currentTimeMillis(),
    val digestsSha1Hex: String? = null,
)
