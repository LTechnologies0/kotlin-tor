package org.kotlintor.hs

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes
import java.time.Duration
import java.time.Instant

class HsKeyBlindTest {
    @Test
    fun `arti C-tor key blinding test vectors`() {
        // From tor-hscrypto pk.rs key_blinding_testvec (generated with C Tor).
        val id = hexToBytes("833990B085C1A688C1D4C8B1F6B56AFAF5A2ECA674449E1D704F83765CCB7BC6")
        val period = HsTimePeriod.containing(
            Instant.parse("1973-05-20T01:50:33Z"),
            lengthMinutes = 1440,
            epochOffset = Duration.ofHours(12),
        )
        assertEquals(1234L, period.intervalNum)

        val h = HsKeyBlind.blindingFactor(id, period)
        assertArrayEquals(
            hexToBytes("379E50DB31FEE6775ABD0AF6FB7C371E060308F4F847DB09FE4CFE13AF602287"),
            h,
        )

        val blinded = HsKeyBlind.blindPublicKey(id, period)
        assertArrayEquals(
            hexToBytes("3A50BF210E8F9EE955AE0014F7A6917FB65EBF098A86305ABB508D1A7291B6D5"),
            blinded,
        )

        val sub = HsKeyBlind.subcredential(id, blinded)
        assertArrayEquals(
            hexToBytes("635D55907816E8D76398A675A50B1C2F3E36B42A5CA77BA3A0441285161AE07D"),
            sub,
        )
    }

    @Test
    fun `arti hsdir index test vectors (C Tor test_hs_indexes)`() {
        val period = HsTimePeriod.containing(
            Instant.parse("1970-02-13T01:00:00Z"),
            lengthMinutes = 1440,
            epochOffset = Duration.ofHours(12),
        )
        assertEquals(42L, period.intervalNum)
        val blindId = ByteArray(32) { 0x42 }
        val svc = HsKeyBlind.serviceIndex(blindId, replica = 1, period = period)
        assertArrayEquals(
            hexToBytes("37e5cbbd56a22823714f18f1623ece5983a0d64c78495a8cfab854245e5f9a8a"),
            svc,
        )
        val relayId = ByteArray(32) { 0x42 }
        val srv = ByteArray(32) { 0x43 }
        val relay = HsKeyBlind.relayIndex(relayId, srv, period)
        assertArrayEquals(
            hexToBytes("db475361014a09965e7e5e4d4a25b8f8d4b8f16cb1d8a7e95eed50249cc1a2d5"),
            relay,
        )
    }
}
