package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path

class DirCacheTest {
    @TempDir
    lateinit var tmp: Path

    @Test
    fun `serves cached consensus`() {
        Files.writeString(tmp.resolve("cached-consensus"), "network-status-version 3\nok\n")
        val cache = DirCache(tmp)
        val resp = String(cache.handleHttp("GET /tor/status-vote/current/consensus HTTP/1.0\r\n\r\n"))
        assertTrue(resp.startsWith("HTTP/1.0 200"))
        assertTrue(resp.contains("network-status-version 3"))
    }

    @Test
    fun `404 when missing`() {
        val cache = DirCache(tmp)
        val resp = String(cache.handleHttp("GET /tor/status-vote/current/consensus HTTP/1.0\r\n\r\n"))
        assertTrue(resp.startsWith("HTTP/1.0 404"))
    }

    @Test
    fun `serves descriptor by fingerprint`() {
        val d = tmp.resolve("cached-descriptors")
        Files.createDirectories(d)
        Files.writeString(d.resolve("AABBCC"), "router test 1.2.3.4 9001 0 0\n")
        val cache = DirCache(tmp)
        val resp = String(cache.handleHttp("GET /tor/server/fp/AABBCC HTTP/1.0\r\n\r\n"))
        assertTrue(resp.startsWith("HTTP/1.0 200"))
        assertTrue(resp.contains("router test"))
    }
}
