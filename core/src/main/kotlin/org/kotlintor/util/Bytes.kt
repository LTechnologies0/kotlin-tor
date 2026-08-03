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

fun u16be(value: Int): ByteArray =
    byteArrayOf(((value ushr 8) and 0xff).toByte(), (value and 0xff).toByte())

fun u32be(value: Long): ByteArray =
    ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value.toInt()).array()

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
    fun nextDouble(): Double = random.nextDouble()
}
