package org.kotlintor.os

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class WinServiceTest {
    @Test
    fun `winsw xml contains service id`() {
        val xml = WinService.winswXml()
        assertTrue(xml.contains("<id>kotlin-tor</id>"))
        assertTrue(xml.contains("cli.jar"))
        assertTrue(WinService.scCreateCommand().startsWith("sc create kotlin-tor"))
    }
}
