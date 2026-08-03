package org.kotlintor.compress

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ZstdLzmaProvidersTest {
    @Test
    fun `zstd roundtrip and detect`() {
        assertTrue(TorCompress.supports(CompressMethod.ZSTD))
        val plain = "kotlin-tor zstd compress vector".repeat(20).toByteArray()
        val c = TorCompress.compress(plain, CompressMethod.ZSTD)
        assertEquals(CompressMethod.ZSTD, TorCompress.detect(c))
        assertArrayEquals(plain, TorCompress.uncompress(c, CompressMethod.ZSTD))
    }

    @Test
    fun `lzma xz roundtrip and detect`() {
        assertTrue(TorCompress.supports(CompressMethod.LZMA))
        val plain = "kotlin-tor lzma/xz compress vector".repeat(20).toByteArray()
        val c = TorCompress.compress(plain, CompressMethod.LZMA)
        assertEquals(CompressMethod.LZMA, TorCompress.detect(c))
        assertArrayEquals(plain, TorCompress.uncompress(c, CompressMethod.LZMA))
    }

    @Test
    fun `negotiate prefers zstd when listed`() {
        assertEquals(CompressMethod.ZSTD, TorCompress.negotiate("x-zstd, gzip, identity"))
    }
}
