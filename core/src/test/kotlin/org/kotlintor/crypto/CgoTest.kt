package org.kotlintor.crypto

import java.io.File
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.util.hexToBytes

/**
 * Prop359 CGO building-block vectors from Arti
 * (`crates/tor-proto/testdata/cgo_{et,prf,uiv}.rs`).
 */
class CgoTest {
    private fun load(name: String): String {
        val fromClasspath = javaClass.classLoader.getResource("cgo/$name")
        if (fromClasspath != null) return fromClasspath.readText()
        val candidates = listOf(File("/tmp/$name"), File("/tmp/arti_testdata/$name"))
        return candidates.first { it.isFile }.readText()
    }

    @Test
    fun `et zero encrypt is AES identity`() {
        val keys = ByteArray(32)
        val tweak = ByteArray(Cgo.TLEN_ET)
        val m = ByteArray(16)
        val out = Cgo.Et.encrypt(keys, tweak, m)
        assertEquals("66e94bd4ef8a2c3b884cfa59ca342b2e", out.joinToString("") { "%02x".format(it) })
    }

    @Test
    fun `et matches arti vectors`() {
        val src = load("cgo_et.rs")
        val cases = Regex(
            """\(\s*// Encrypt\s*(True|False),\s*// \(KB,KU\)\s*"([0-9a-f]+)",\s*// T\s*"([0-9a-f]+)",\s*// M\s*"([0-9a-f]+)",\s*// OUTPUT\s*"([0-9a-f]+)"\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(src).toList()
        assertTrue(cases.size >= 6, "expected several ET vectors, got ${cases.size}")
        for (m in cases) {
            val encrypt = m.groupValues[1] == "True"
            val keys = hexToBytes(m.groupValues[2])
            val t = hexToBytes(m.groupValues[3])
            val block = hexToBytes(m.groupValues[4])
            val expect = hexToBytes(m.groupValues[5])
            require(keys.size == 32 && t.size == Cgo.TLEN_ET && block.size == 16)
            val got = if (encrypt) Cgo.Et.encrypt(keys, t, block) else Cgo.Et.decrypt(keys, t, block)
            assertArrayEquals(expect, got, "ET encrypt=$encrypt keys=${m.groupValues[2].take(8)}…")
        }
    }

    @Test
    fun `prf matches arti vectors`() {
        val src = load("cgo_prf.rs")
        val cases = Regex(
            """\(\s*// K,B\s*"([0-9a-f]+)",\s*// T\s*([01]),\s*// t\s*"([0-9a-f]+)",\s*// OUTPUT\s*"([0-9a-f]+)"\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(src).toList()
        assertTrue(cases.size >= 6, "expected several PRF vectors, got ${cases.size}")
        for (m in cases) {
            val keys = hexToBytes(m.groupValues[1])
            val t1 = m.groupValues[2] == "1"
            val tweak = hexToBytes(m.groupValues[3])
            val expect = hexToBytes(m.groupValues[4])
            require(keys.size == 32 && tweak.size == 16)
            val got = Cgo.Prf.stream(keys, tweak, t1, expect.size)
            assertArrayEquals(expect, got, "PRF t1=$t1 keys=${m.groupValues[1].take(8)}…")
        }
    }

    @Test
    fun `uiv matches arti vectors`() {
        val src = load("cgo_uiv.rs")
        val cases = Regex(
            """\(\s*// Encrypt\s*(True|False),\s*// \(J,S\)\s*"([0-9a-f]+)",\s*// H\s*"([0-9a-f]+)",\s*// X_L\s*"([0-9a-f]+)",\s*// X_R\s*"([0-9a-f]+)",\s*// Output=\(Y_L, Y_R\)\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\)\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(src).toList()
        assertTrue(cases.size >= 6, "expected several UIV vectors, got ${cases.size}")
        for (m in cases) {
            val encrypt = m.groupValues[1] == "True"
            val keys = hexToBytes(m.groupValues[2])
            val h = hexToBytes(m.groupValues[3])
            val xl = hexToBytes(m.groupValues[4])
            val xr = hexToBytes(m.groupValues[5])
            val yl = hexToBytes(m.groupValues[6])
            val yr = hexToBytes(m.groupValues[7])
            require(keys.size == Cgo.KLEN_UIV && h.size == 17)
            require(xl.size == 16 && xr.size == Cgo.PAYLOAD_LEN)
            require(yl.size == 16 && yr.size == Cgo.PAYLOAD_LEN)
            val cell = xl + xr
            val got = if (encrypt) Cgo.Uiv.encrypt(keys, h, cell) else Cgo.Uiv.decrypt(keys, h, cell)
            assertArrayEquals(yl + yr, got, "UIV encrypt=$encrypt keys=${m.groupValues[2].take(8)}…")
        }
    }

    @Test
    fun `uiv round trip`() {
        val keys = hexToBytes(
            "f32563514c60b34aff6107deb5a324e97833eb0da2c49ca86c3c977974b18d21" +
                "48fc035e8d2d7bd6f29cfadd9b947caefc5fe707827619134babb436252c0391",
        )
        val h = hexToBytes("a97040573c1aae79986f933d6286e6e069")
        val xl = hexToBytes("84a8b1973bd819e817aef7a866bd2016")
        val xr = ByteArray(Cgo.PAYLOAD_LEN) { it.toByte() }
        val cell = xl + xr
        val enc = Cgo.Uiv.encrypt(keys, h, cell)
        val dec = Cgo.Uiv.decrypt(keys, h, enc)
        assertArrayEquals(cell, dec)
    }

    @Test
    fun `uiv update matches arti vectors`() {
        val src = load("cgo_uiv.rs")
        val section = src.substringAfter("UIV_UPDATE_TEST_VECTORS")
        val cases = Regex(
            """\(\s*// \(J,S\)\s*"([0-9a-f]+)",\s*// N\s*"([0-9a-f]+)",\s*// Output=\(\(J',S'\), N'\)\s*\(\s*"([0-9a-f]+)",\s*"([0-9a-f]+)"\s*\)\s*,?\s*\)""",
            RegexOption.DOT_MATCHES_ALL,
        ).findAll(section).toList()
        assertTrue(cases.size >= 5, "expected UPDATE vectors, got ${cases.size}")
        for (m in cases) {
            val keys = hexToBytes(m.groupValues[1])
            val nonce = hexToBytes(m.groupValues[2])
            val expectKeys = hexToBytes(m.groupValues[3])
            val expectNonce = hexToBytes(m.groupValues[4])
            val (gotKeys, gotNonce) = Cgo.Uiv.update(keys, nonce)
            assertArrayEquals(expectKeys, gotKeys)
            assertArrayEquals(expectNonce, gotNonce)
        }
    }
}
