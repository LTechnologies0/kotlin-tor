package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

class DirHttpTest {
    @Test
    fun `splitHttpBody returns 2xx body`() {
        val raw = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello".toByteArray(Charsets.ISO_8859_1)
        assertEquals("hello", DirHttp.splitHttpBody(raw).toString(Charsets.US_ASCII))
    }

    @Test
    fun `splitHttpBody rejects non-2xx`() {
        val raw = "HTTP/1.0 500 Internal Server Error\r\n\r\nno".toByteArray(Charsets.ISO_8859_1)
        assertThrows(IllegalStateException::class.java) { DirHttp.splitHttpBody(raw) }
    }

    @Test
    fun `httpGetOverPipe rejects CRLF in path`() {
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking {
                DirHttp.httpGetOverPipe({ }, { ByteArray(0) }, "/tor/\r\nHost: evil")
            }
        }
    }

    @Test
    fun `readBounded rejects oversized body`() {
        val big = ByteArray(64) { 1 }
        assertThrows(IllegalStateException::class.java) {
            DirHttp.readBounded(ByteArrayInputStream(big), maxBytes = 16)
        }
    }

    @Test
    fun `readBounded copies exact bytes under cap`() {
        val src = "abc".toByteArray(StandardCharsets.US_ASCII)
        assertArrayEquals(src, DirHttp.readBounded(ByteArrayInputStream(src), maxBytes = 16))
    }
}
