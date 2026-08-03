package org.kotlintor.crypto

import java.io.File
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes

/** Prop359 hop-layer vectors from Arti `cgo_relay.rs` / `cgo_client.rs`. */
class CgoHopTest {
    private fun load(name: String): String {
        val fromClasspath = javaClass.classLoader.getResource("cgo/$name")
        if (fromClasspath != null) return fromClasspath.readText()
        return File("/tmp/$name").readText()
    }

    @Test
    fun `relay forward matches arti vectors`() {
        val src = load("cgo_relay.rs")
        val section = src.substringBefore("CGO_RELAY_ORIGINATE_TEST_VECTORS")
        val cases = Regex(
            """\(\s*// Inbound\s*(True|False),\s*// R = \(K, N, T'\)\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\),\s*// AD\s*"([0-9a-f]+)",\s*// T\s*"([0-9a-f]+)",\s*// C\s*"([0-9a-f]+)",\s*// Output=\(R', \(T_out, C_out\)\)\s*\(\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\),\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\)\s*\)\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(section).toList()
        assertTrue(cases.size >= 4, "expected relay vectors, got ${cases.size}")
        for (m in cases) {
            val inbound = m.groupValues[1] == "True"
            val hop = CgoHop(
                keys = hexToBytes(m.groupValues[2]),
                nonce = hexToBytes(m.groupValues[3]),
                tag = hexToBytes(m.groupValues[4]),
            )
            val cmd = hexToBytes(m.groupValues[5]).single().toInt() and 0xff
            val cell = hexToBytes(m.groupValues[6] + m.groupValues[7])
            require(cell.size == Cgo.CELL_DATA_LEN)
            if (inbound) hop.relayEncryptInbound(cmd, cell)
            else hop.relayDecryptOutbound(cmd, cell)
            val (k, n, t) = hop.snapshot()
            assertArrayEquals(hexToBytes(m.groupValues[8]), k, "keys inbound=$inbound")
            assertArrayEquals(hexToBytes(m.groupValues[9]), n, "nonce inbound=$inbound")
            assertArrayEquals(hexToBytes(m.groupValues[10]), t, "tag inbound=$inbound")
            assertArrayEquals(
                hexToBytes(m.groupValues[11] + m.groupValues[12]),
                cell,
                "cell inbound=$inbound",
            )
        }
    }

    @Test
    fun `relay originate matches arti vectors`() {
        val src = load("cgo_relay.rs")
        val section = src.substringAfter("CGO_RELAY_ORIGINATE_TEST_VECTORS")
        val cases = Regex(
            """\(\s*// R = \(K, N, T'\)\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\),\s*// AD\s*"([0-9a-f]+)",\s*// M\s*"([0-9a-f]+)",\s*// Output=\(R', \(T_out, C_out\)\)\s*\(\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\),\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\)\s*\)\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(section).toList()
        assertTrue(cases.size >= 4, "expected originate vectors, got ${cases.size}")
        for (m in cases) {
            val hop = CgoHop(
                keys = hexToBytes(m.groupValues[1]),
                nonce = hexToBytes(m.groupValues[2]),
                tag = hexToBytes(m.groupValues[3]),
            )
            val cmd = hexToBytes(m.groupValues[4]).single().toInt() and 0xff
            val payload = hexToBytes(m.groupValues[5])
            require(payload.size == Cgo.PAYLOAD_LEN)
            val cell = ByteArray(Cgo.CELL_DATA_LEN)
            payload.copyInto(cell, Cgo.TAG_LEN)
            hop.relayOriginate(cmd, cell)
            val (k, n, t) = hop.snapshot()
            assertArrayEquals(hexToBytes(m.groupValues[6]), k)
            assertArrayEquals(hexToBytes(m.groupValues[7]), n)
            assertArrayEquals(hexToBytes(m.groupValues[8]), t)
            assertArrayEquals(hexToBytes(m.groupValues[9] + m.groupValues[10]), cell)
        }
    }

    @Test
    fun `client originate hop path matches arti vectors`() {
        val src = load("cgo_client.rs")
        // Each case: S[3]=(K,N,T')×3, hop index d (1-based), AD, M(payload), Output=(S'[3], (T,C))
        val hopTriple = """\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\)"""
        val cases = Regex(
            """\(\s*// S\[\]\s*\[\s*$hopTriple,\s*$hopTriple,\s*$hopTriple\s*\],\s*// d\s*(\d+),\s*// AD\s*"([0-9a-f]+)",\s*// M\s*"([0-9a-f]+)",\s*// Output=\(S'\[\], T, C\)\s*\(\s*\[\s*$hopTriple,\s*$hopTriple,\s*$hopTriple\s*\],\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\)\s*\)\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(src).toList()
        assertTrue(cases.size >= 4, "expected client originate vectors, got ${cases.size}")
        for (m in cases) {
            val hops = Array(3) { i ->
                val base = 1 + i * 3
                CgoHop(
                    keys = hexToBytes(m.groupValues[base]),
                    nonce = hexToBytes(m.groupValues[base + 1]),
                    tag = hexToBytes(m.groupValues[base + 2]),
                )
            }
            val targetHop = m.groupValues[10].toInt() // 1-based
            val cmd = hexToBytes(m.groupValues[11]).single().toInt() and 0xff
            val payload = hexToBytes(m.groupValues[12])
            require(payload.size == Cgo.PAYLOAD_LEN)
            val cell = ByteArray(Cgo.CELL_DATA_LEN)
            payload.copyInto(cell, Cgo.TAG_LEN)

            // Arti: for hop_idx in (0..hop).rev() { if hop_idx==hop { originate } else encrypt }
            val hopIdx = targetHop - 1
            for (i in hopIdx downTo 0) {
                if (i == hopIdx) hops[i].clientOriginate(cmd, cell)
                else hops[i].clientEncryptOutbound(cmd, cell)
            }

            for (i in 0 until 3) {
                val base = 13 + i * 3
                val (k, n, t) = hops[i].snapshot()
                assertArrayEquals(hexToBytes(m.groupValues[base]), k, "hop $i keys")
                assertArrayEquals(hexToBytes(m.groupValues[base + 1]), n, "hop $i nonce")
                assertArrayEquals(hexToBytes(m.groupValues[base + 2]), t, "hop $i tag")
            }
            assertArrayEquals(
                hexToBytes(m.groupValues[22] + m.groupValues[23]),
                cell,
                "client cell hop=$targetHop",
            )
        }
    }
}
