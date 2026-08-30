package org.kotlintor.or

/** C Tor `hsdir_index_t`. */
data class HsDirIndex(
    val first: ByteArray,
    val second: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is HsDirIndex && first.contentEquals(other.first) && second.contentEquals(other.second)
    override fun hashCode(): Int = first.contentHashCode() xor second.contentHashCode()
}
