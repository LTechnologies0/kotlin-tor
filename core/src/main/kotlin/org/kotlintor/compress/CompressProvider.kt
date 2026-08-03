package org.kotlintor.compress

/**
 * Frame detectors for optional codecs (C Tor `lib/compress` magic bytes).
 * Real encode/decode requires a registered [CompressProvider].
 */
object ZstdFrame {
    /** ZSTD magic little-endian 0xFD2FB528. */
    fun looksLike(input: ByteArray): Boolean =
        input.size >= 4 &&
            (input[0].toInt() and 0xff) == 0x28 &&
            (input[1].toInt() and 0xff) == 0xB5 &&
            (input[2].toInt() and 0xff) == 0x2F &&
            (input[3].toInt() and 0xff) == 0xFD
}

object LzmaFrame {
    /** xz stream header magic. */
    fun looksLike(input: ByteArray): Boolean =
        input.size >= 6 &&
            input[0] == 0xFD.toByte() &&
            input[1] == 0x37.toByte() &&
            input[2] == 0x7A.toByte() &&
            input[3] == 0x58.toByte() &&
            input[4] == 0x5A.toByte() &&
            input[5] == 0x00.toByte()
}
