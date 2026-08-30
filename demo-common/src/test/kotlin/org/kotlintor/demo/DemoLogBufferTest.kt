package org.kotlintor.demo

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets

class DemoLogBufferTest {
    @Test
    fun `tee captures complete lines without OUT prefix accumulation`() {
        DemoLogBuffer.install()
        DemoLogBuffer.clear()
        println("hop-a ready")
        println("hop-b ready")
        System.err.println("stream failed: boom")
        val snap = DemoLogBuffer.snapshot()
        assertTrue(snap.contains("[stdout] hop-a ready"), snap)
        assertTrue(snap.contains("[stdout] hop-b ready"), snap)
        assertTrue(snap.contains("[stderr] stream failed: boom"), snap)
        assertFalse(snap.contains("OUThop"), snap)
        assertFalse(snap.contains("OUTOUT"), snap)
        assertFalse(snap.contains("hop-a readyhop-b"), snap)
    }

    @Test
    fun `structured append echoes without OUT accumulation`() {
        DemoLogBuffer.install()
        DemoLogBuffer.clear()
        DemoLogBuffer.append("circ", "CIRC 1 BUILDING HOP=1")
        DemoLogBuffer.append("session", "started ok")
        val snap = DemoLogBuffer.snapshot()
        assertTrue(snap.contains("[circ] CIRC 1 BUILDING HOP=1"), snap)
        assertTrue(snap.contains("[session] started ok"), snap)
        assertFalse(snap.contains("OUTOUT"), snap)
        assertFalse(snap.contains("[stdout] CIRC"), snap)
    }

    @Test
    fun `printstream over tee preserves console bytes`() {
        val sink = ByteArrayOutputStream()
        val lines = ArrayList<String>()
        val tee = object : java.io.OutputStream() {
            private val buf = ByteArrayOutputStream()
            override fun write(b: Int) {
                sink.write(b)
                if (b == '\n'.code) {
                    lines += buf.toString(StandardCharsets.UTF_8)
                    buf.reset()
                } else if (b != '\r'.code) {
                    buf.write(b)
                }
            }
            override fun write(b: ByteArray, off: Int, len: Int) {
                for (i in off until off + len) write(b[i].toInt() and 0xff)
            }
        }
        val ps = PrintStream(tee, true, StandardCharsets.UTF_8)
        ps.println("alpha")
        ps.println("beta")
        assertTrue(sink.toString(StandardCharsets.UTF_8).contains("alpha\n"))
        assertTrue(sink.toString(StandardCharsets.UTF_8).contains("beta\n"))
        assertTrue(lines == listOf("alpha", "beta"), lines.toString())
    }
}
