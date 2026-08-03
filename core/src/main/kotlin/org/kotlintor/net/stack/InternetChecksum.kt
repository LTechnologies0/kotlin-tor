package org.kotlintor.net.stack

/**
 * Internet checksum (RFC 1071) used by IPv4 / TCP / UDP / ICMP.
 */
object InternetChecksum {
    fun compute(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xffff) + (sum ushr 16)
        }
        return (sum.inv() and 0xffff).toInt()
    }

    fun fold(sum: Long): Int {
        var s = sum
        while (s ushr 16 != 0L) s = (s and 0xffff) + (s ushr 16)
        return (s.inv() and 0xffff).toInt()
    }
}
