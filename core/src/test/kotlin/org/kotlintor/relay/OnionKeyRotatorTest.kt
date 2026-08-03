package org.kotlintor.relay

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class OnionKeyRotatorTest {
    @TempDir
    lateinit var dir: Path

    @Test
    fun `load generate and force rotate`() {
        val rot = OnionKeyRotator(dir, lifetimeDays = 0)
        val first = rot.loadOrGenerate().current.publicKey.copyOf()
        assertTrue(rot.maybeRotate())
        val second = rot.current().publicKey
        assertFalse(first.contentEquals(second))
        assertNotNull(rot.previous())
        assertTrue(first.contentEquals(rot.previous()!!.publicKey))
    }
}
