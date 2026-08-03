package org.kotlintor.os

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS

class SeccompBpfTest {
    @Test
    fun `packFilter writes little-endian sock_filter`() {
        val prog = SeccompBpf.buildAllowAllFilter()
        val bytes = SeccompBpf.packFilter(prog)
        assertEquals(16, bytes.size)
        // first insn: BPF_LD|BPF_W|BPF_ABS = 0x20, k=4
        assertEquals(0x20.toByte(), bytes[0])
        assertEquals(0, bytes[1].toInt())
        assertEquals(4, bytes[4].toInt() and 0xff)
    }

    @Test
    fun `tor-lite deny filter has load + denys + allow`() {
        val prog = SeccompBpf.buildTorLiteDenyFilter()
        // 1 LD + 6*(JEQ+KILL) + ALLOW = 14
        assertEquals(14, prog.size)
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    fun `install allow-all is best-effort on Linux`() {
        // May fail without privileges / in restricted CI — must not throw.
        val r = SeccompBpf.install(denyPtrace = false)
        assertTrue(r.note.isNotEmpty())
    }
}
