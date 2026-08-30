package org.kotlintor

import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.kotlintor.config.TorConfig
import java.nio.file.Files

class DnsRequestIsolationTest {
    @Test
    fun dnsRequestKeysAreUniquePerCall() {
        val dir = Files.createTempDirectory("ktor-dns-iso")
        val client = TorClient(TorConfig(dataDirectory = dir), kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default))
        val a = client.newDnsRequestIsolationKey("example.com")
        val b = client.newDnsRequestIsolationKey("example.com")
        assertTrue(a.startsWith("dns:example.com|"))
        assertTrue(b.startsWith("dns:example.com|"))
        assertNotEquals(a, b)
    }
}
