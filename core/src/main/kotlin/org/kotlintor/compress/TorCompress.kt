package org.kotlintor.compress

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/**
 * Directory document compression (C Tor `lib/compress`).
 *
 * Built-in: none / gzip / zlib. ZSTD (zstd-jni) and LZMA/XZ (tukaani) register
 * automatically via [registerBuiltinProviders].
 */
enum class CompressMethod {
    NONE,
    GZIP,
    ZLIB,
    LZMA,
    ZSTD,
    UNKNOWN,
}

enum class CompressionLevel { BEST, HIGH, MEDIUM, LOW }

/**
 * Pluggable compress backend (C Tor `lib/compress` provider hooks).
 */
interface CompressProvider {
    val method: CompressMethod
    fun compress(input: ByteArray, level: CompressionLevel): ByteArray
    fun uncompress(input: ByteArray): ByteArray
}

object TorCompress {
    private val extraProviders = java.util.concurrent.ConcurrentHashMap<CompressMethod, CompressProvider>()

    init {
        runCatching { registerBuiltinProviders() }
    }

    fun registerProvider(provider: CompressProvider) {
        extraProviders[provider.method] = provider
    }

    fun unregisterProvider(method: CompressMethod) {
        extraProviders.remove(method)
    }

    fun provider(method: CompressMethod): CompressProvider? = extraProviders[method]

    fun supports(method: CompressMethod): Boolean =
        method == CompressMethod.NONE ||
            method == CompressMethod.GZIP ||
            method == CompressMethod.ZLIB ||
            provider(method) != null

    fun methodName(method: CompressMethod): String = when (method) {
        CompressMethod.NONE -> "identity"
        CompressMethod.GZIP -> "gzip"
        CompressMethod.ZLIB -> "deflate"
        CompressMethod.LZMA -> "x-tor-lzma"
        CompressMethod.ZSTD -> "x-zstd"
        CompressMethod.UNKNOWN -> "unknown"
    }

    fun byName(name: String): CompressMethod = when (name.lowercase()) {
        "identity", "none" -> CompressMethod.NONE
        "gzip", "x-gzip" -> CompressMethod.GZIP
        "deflate", "zlib", "x-zlib" -> CompressMethod.ZLIB
        "x-tor-lzma", "lzma" -> CompressMethod.LZMA
        "x-zstd", "zstd" -> CompressMethod.ZSTD
        else -> CompressMethod.UNKNOWN
    }

    fun detect(input: ByteArray): CompressMethod {
        if (input.size >= 2 && input[0] == 0x1f.toByte() && input[1] == 0x8b.toByte()) {
            return CompressMethod.GZIP
        }
        if (input.size >= 2 && input[0] == 0x78.toByte()) {
            return CompressMethod.ZLIB
        }
        if (ZstdFrame.looksLike(input)) return CompressMethod.ZSTD
        if (LzmaFrame.looksLike(input)) return CompressMethod.LZMA
        return CompressMethod.NONE
    }

    fun compress(input: ByteArray, method: CompressMethod, level: CompressionLevel = CompressionLevel.MEDIUM): ByteArray {
        provider(method)?.let { return it.compress(input, level) }
        require(method == CompressMethod.NONE || method == CompressMethod.GZIP || method == CompressMethod.ZLIB) {
            "unsupported method $method (register CompressProvider)"
        }
        return when (method) {
            CompressMethod.NONE -> input
            CompressMethod.GZIP -> {
                val bos = ByteArrayOutputStream()
                GZIPOutputStream(bos).use { it.write(input) }
                bos.toByteArray()
            }
            CompressMethod.ZLIB -> {
                val bos = ByteArrayOutputStream()
                val def = Deflater(deflaterLevel(level), false)
                DeflaterOutputStream(bos, def).use { it.write(input) }
                bos.toByteArray()
            }
            else -> error("unsupported")
        }
    }

    fun uncompress(input: ByteArray, method: CompressMethod = detect(input)): ByteArray {
        provider(method)?.let { return it.uncompress(input) }
        require(method == CompressMethod.NONE || method == CompressMethod.GZIP || method == CompressMethod.ZLIB) {
            "unsupported method $method (register CompressProvider)"
        }
        return when (method) {
            CompressMethod.NONE -> input
            CompressMethod.GZIP ->
                GZIPInputStream(ByteArrayInputStream(input)).use { it.readBytes() }
            CompressMethod.ZLIB -> {
                val inflater = Inflater(false)
                InflaterInputStream(ByteArrayInputStream(input), inflater).use { it.readBytes() }
            }
            else -> error("unsupported")
        }
    }

    /** Negotiate Accept-Encoding style preference list → best supported. */
    fun negotiate(acceptEncoding: String): CompressMethod {
        val wanted = acceptEncoding.split(',').map { it.trim().substringBefore(';').lowercase() }
        for (w in wanted) {
            val m = byName(w)
            if (supports(m) && m != CompressMethod.NONE) return m
        }
        return CompressMethod.NONE
    }

    fun isCompressionBomb(sizeIn: Long, sizeOut: Long, maxRatio: Int = 100): Boolean {
        if (sizeIn <= 0) return sizeOut > 1_000_000
        return sizeOut > sizeIn * maxRatio || sizeOut > 64L * 1024 * 1024
    }

    private fun deflaterLevel(level: CompressionLevel): Int = when (level) {
        CompressionLevel.BEST -> Deflater.BEST_COMPRESSION
        CompressionLevel.HIGH -> 7
        CompressionLevel.MEDIUM -> Deflater.DEFAULT_COMPRESSION
        CompressionLevel.LOW -> Deflater.BEST_SPEED
    }
}
