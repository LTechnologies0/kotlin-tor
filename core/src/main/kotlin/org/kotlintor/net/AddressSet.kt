package org.kotlintor.net

import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLongArray

/**
 * Probabilistic address set (C Tor `address_set_t` / bloomfilt).
 *
 * False negatives cannot occur for inserted addresses; false positives are
 * possible. Used for exit-policy helpers and DoS address tracking.
 */
class AddressSet(
    maxAddressesGuess: Int = 1024,
    private val hashCount: Int = 4,
) {
    private val bits: AtomicLongArray
    private val bitLen: Int

    init {
        val n = maxAddressesGuess.coerceIn(64, 1_000_000)
        // ~10 bits per element
        bitLen = (n * 10).coerceAtLeast(256)
        val words = (bitLen + 63) / 64
        bits = AtomicLongArray(words)
    }

    fun add(addr: InetAddress) {
        for (i in 0 until hashCount) {
            val idx = index(addr, i)
            val w = idx ushr 6
            val b = 1L shl (idx and 63)
            while (true) {
                val cur = bits.get(w)
                if (bits.compareAndSet(w, cur, cur or b)) break
            }
        }
    }

    fun addIpv4h(hostOrder: Int) {
        val bytes = byteArrayOf(
            ((hostOrder ushr 24) and 0xff).toByte(),
            ((hostOrder ushr 16) and 0xff).toByte(),
            ((hostOrder ushr 8) and 0xff).toByte(),
            (hostOrder and 0xff).toByte(),
        )
        add(InetAddress.getByAddress(bytes))
    }

    /** Alias matching C Tor `address_set_add_ipv4h`. */
    fun addIpv4HostOrder(hostOrder: Int) = addIpv4h(hostOrder)

    fun probablyContains(addr: InetAddress): Boolean {
        for (i in 0 until hashCount) {
            val idx = index(addr, i)
            val w = idx ushr 6
            val b = 1L shl (idx and 63)
            if ((bits.get(w) and b) == 0L) return false
        }
        return true
    }

    fun add(host: String) {
        runCatching { InetAddress.getByName(host) }.getOrNull()?.let { add(it) }
    }

    /** Clear all bits (tests / DoS reset; C Tor recreates the set). */
    fun clear() {
        for (i in 0 until bits.length()) bits.set(i, 0L)
    }

    private fun index(addr: InetAddress, salt: Int): Int {
        val raw = addr.address
        var h = salt * -0x61C88647
        for (b in raw) {
            h = (h xor (b.toInt() and 0xff)) * 0x01000193
        }
        return (h and 0x7fff_ffff) % bitLen
    }

    companion object {
        /** C Tor `address_set_new`. */
        fun new(maxAddressesGuess: Int = 1024, hashCount: Int = 4): AddressSet =
            AddressSet(maxAddressesGuess, hashCount)

        fun of(vararg hosts: String): AddressSet {
            val set = AddressSet(hosts.size.coerceAtLeast(8) * 4)
            hosts.forEach { set.add(it) }
            return set
        }
    }
}
