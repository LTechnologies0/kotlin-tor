package org.kotlintor.compress

import com.github.luben.zstd.Zstd
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZInputStream
import org.tukaani.xz.XZOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * Real ZSTD provider via zstd-jni (C Tor `compress_zstd.c`).
 */
object ZstdCompressProvider : CompressProvider {
    override val method: CompressMethod = CompressMethod.ZSTD

    override fun compress(input: ByteArray, level: CompressionLevel): ByteArray {
        val lvl = when (level) {
            CompressionLevel.BEST -> 19
            CompressionLevel.HIGH -> 12
            CompressionLevel.MEDIUM -> 3
            CompressionLevel.LOW -> 1
        }
        return Zstd.compress(input, lvl)
    }

    override fun uncompress(input: ByteArray): ByteArray {
        val size = Zstd.decompressedSize(input)
        require(size >= 0 && size < 64L * 1024 * 1024) { "zstd size invalid/bomb" }
        return Zstd.decompress(input, size.toInt())
    }

    fun register() {
        TorCompress.registerProvider(this)
    }
}

/**
 * Real XZ/LZMA2 provider via tukaani xz (C Tor `compress_lzma.c`).
 */
object LzmaCompressProvider : CompressProvider {
    override val method: CompressMethod = CompressMethod.LZMA

    override fun compress(input: ByteArray, level: CompressionLevel): ByteArray {
        val opts = LZMA2Options(
            when (level) {
                CompressionLevel.BEST -> LZMA2Options.PRESET_MAX
                CompressionLevel.HIGH -> 7
                CompressionLevel.MEDIUM -> LZMA2Options.PRESET_DEFAULT
                CompressionLevel.LOW -> LZMA2Options.PRESET_MIN
            },
        )
        val bos = ByteArrayOutputStream()
        XZOutputStream(bos, opts).use { it.write(input) }
        return bos.toByteArray()
    }

    override fun uncompress(input: ByteArray): ByteArray =
        XZInputStream(ByteArrayInputStream(input)).use { it.readBytes() }

    fun register() {
        TorCompress.registerProvider(this)
    }
}

/** Register built-in native/JAR compress backends. */
fun TorCompress.registerBuiltinProviders() {
    ZstdCompressProvider.register()
    LzmaCompressProvider.register()
}
