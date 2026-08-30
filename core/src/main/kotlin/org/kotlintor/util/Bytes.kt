package org.kotlintor.util

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

fun ByteArray.toHex(limit: Int = size): String =
    take(limit).joinToString("") { "%02x".format(it) }

fun hexToBytes(hex: String): ByteArray {
    val clean = hex.trim().replace(" ", "").replace(":", "")
    require(clean.length % 2 == 0) { "hex length must be even" }
    return ByteArray(clean.length / 2) { i ->
        clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

fun ByteArray.secureWipe() {
    fill(0)
}

/** Constant-time equality for secrets (MAC, cookies, password digests). */
fun constantTimeEquals(a: ByteArray?, b: ByteArray?): Boolean {
    if (a === b) return true
    if (a == null || b == null) return false
    if (a.size != b.size) return false
    var diff = 0
    for (i in a.indices) {
        diff = diff or (a[i].toInt() xor b[i].toInt())
    }
    return diff == 0
}

fun concat(vararg parts: ByteArray): ByteArray {
    val out = ByteArray(parts.sumOf { it.size })
    var off = 0
    for (p in parts) {
        p.copyInto(out, off)
        off += p.size
    }
    return out
}

/** Fail-closed check for unsigned 16-bit wire fields (no silent truncate). */
fun requireU16(value: Int): Int {
    require(value in 0..0xffff) { "u16 out of range: $value" }
    return value
}

/** Fail-closed check for unsigned 32-bit wire fields (no silent truncate). */
fun requireU32(value: Long): Long {
    require(value in 0L..0xffffffffL) { "u32 out of range: $value" }
    return value
}

fun u16be(value: Int): ByteArray {
    val v = requireU16(value)
    return byteArrayOf(((v ushr 8) and 0xff).toByte(), (v and 0xff).toByte())
}

fun u32be(value: Long): ByteArray {
    val v = requireU32(value)
    return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(v.toInt()).array()
}

fun u64be(value: Long): ByteArray =
    ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(value).array()

fun readU16be(buf: ByteArray, offset: Int): Int =
    ((buf[offset].toInt() and 0xff) shl 8) or (buf[offset + 1].toInt() and 0xff)

fun readU32be(buf: ByteArray, offset: Int): Long {
    var v = 0L
    for (i in 0 until 4) {
        v = (v shl 8) or (buf[offset + i].toInt() and 0xff).toLong()
    }
    return v
}

fun readU64be(buf: ByteArray, offset: Int): Long {
    var v = 0L
    for (i in 0 until 8) {
        v = (v shl 8) or (buf[offset + i].toInt() and 0xff).toLong()
    }
    return v
}

object SecureRandomSource {
    private val random = SecureRandom()
    fun nextBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }
    fun nextInt(bound: Int): Int = random.nextInt(bound)
    /** Uniform in `[0, bound)`. Requires [bound] > 0. */
    fun nextLong(bound: Long): Long {
        require(bound > 0) { "bound must be positive" }
        return random.nextLong(bound)
    }
    fun nextDouble(): Double = random.nextDouble()
}

/** Android ART may lack Java 11 [Files.readString]/[Files.writeString] even on API 33 images. */
fun java.nio.file.Path.readTextCompat(): String =
    String(java.nio.file.Files.readAllBytes(this), Charsets.UTF_8)

fun java.nio.file.Path.writeTextCompat(text: CharSequence) {
    java.nio.file.Files.write(this, text.toString().toByteArray(Charsets.UTF_8))
}
