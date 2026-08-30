package org.kotlintor.demo

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.concurrent.CopyOnWriteArrayList

/**
 * In-process log ring for demo UIs.
 *
 * Captures [System.out]/[System.err] via a line-splitting [OutputStream] under a normal
 * [PrintStream] (JDK 21-safe). Structured [append] lines are also echoed to the real
 * console (bypassing the tee) so a terminal session stays visible without the old
 * `OUT`/`ERR` prefix accumulation.
 */
object DemoLogBuffer {
    private const val MAX_LINES = 2_000
    private val lines = ArrayList<String>(256)
    private val listeners = CopyOnWriteArrayList<(String) -> Unit>()
    private val lock = Any()
    private var installed = false

    /** Pre-tee consoles — used to echo structured logs without re-entering capture. */
    @Volatile
    private var consoleOut: PrintStream? = null

    @Volatile
    private var consoleErr: PrintStream? = null

    /** Per-thread: ignore stdout/stderr while we format/store a captured line. */
    private val capturing = ThreadLocal.withInitial { false }

    private val timeFmt: DateTimeFormatter =
        DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault())

    fun install() {
        synchronized(lock) {
            if (installed) return
            val originalOut = System.out
            val originalErr = System.err
            consoleOut = originalOut
            consoleErr = originalErr
            System.setOut(
                PrintStream(
                    LineSplittingStream(originalOut) { appendCaptured("stdout", it) },
                    true,
                    StandardCharsets.UTF_8,
                ),
            )
            System.setErr(
                PrintStream(
                    LineSplittingStream(originalErr) { appendCaptured("stderr", it) },
                    true,
                    StandardCharsets.UTF_8,
                ),
            )
            installed = true
        }
        append("app", "Log capture started")
    }

    /**
     * Structured log for the UI ring + terminal echo.
     * Does not go through System.out (avoids tee re-entry).
     */
    fun append(tag: String, message: String) {
        val line = formatLine(tag, message) ?: return
        storeAndNotify(line)
        // Keep the launching terminal alive: echo everything except raw tee captures
        // (those already hit the console via the tee sink).
        if (tag != "stdout" && tag != "stderr") {
            consoleOut?.println(line)
            consoleOut?.flush()
        }
    }

    /** Capture path from the tee — already printed to the real console by the sink. */
    private fun appendCaptured(tag: String, message: String) {
        val line = formatLine(tag, message) ?: return
        storeAndNotify(line)
    }

    private fun formatLine(tag: String, message: String): String? {
        val ts = timeFmt.format(Instant.now())
        val cleaned = message.replace("\r\n", "\n").replace('\r', '\n')
            .lineSequence()
            .map { it.trimEnd() }
            .filter { it.isNotEmpty() }
            .joinToString(" · ")
        if (cleaned.isEmpty()) return null
        return "$ts [$tag] $cleaned"
    }

    private fun storeAndNotify(line: String) {
        val snapshot: List<(String) -> Unit>
        synchronized(lock) {
            lines += line
            while (lines.size > MAX_LINES) lines.removeAt(0)
            snapshot = listeners.toList()
        }
        val prev = capturing.get()
        capturing.set(true)
        try {
            for (l in snapshot) runCatching { l(line) }
        } finally {
            capturing.set(prev)
        }
    }

    fun clear() {
        synchronized(lock) { lines.clear() }
        append("app", "Logs cleared")
    }

    fun snapshot(): String = synchronized(lock) { lines.joinToString("\n") }

    fun addListener(listener: (String) -> Unit) {
        listeners += listener
    }

    fun removeListener(listener: (String) -> Unit) {
        listeners -= listener
    }

    /**
     * Forwards every byte to [sink] unchanged; emits complete lines (split on `\n`)
     * to [onLine]. `\r` is ignored so `\r\n` and bare `\n` both work.
     */
    private class LineSplittingStream(
        private val sink: OutputStream,
        private val onLine: (String) -> Unit,
    ) : OutputStream() {
        private val lineBuf = ByteArrayOutputStream(256)

        @Synchronized
        override fun write(b: Int) {
            sink.write(b)
            accept(b)
        }

        @Synchronized
        override fun write(buf: ByteArray, off: Int, len: Int) {
            sink.write(buf, off, len)
            val end = off + len
            var i = off
            while (i < end) {
                accept(buf[i].toInt() and 0xff)
                i++
            }
        }

        @Synchronized
        override fun flush() {
            sink.flush()
        }

        @Synchronized
        override fun close() {
            flushLine()
            sink.close()
        }

        private fun accept(c: Int) {
            when (c) {
                '\n'.code -> flushLine()
                '\r'.code -> Unit
                else -> lineBuf.write(c)
            }
        }

        private fun flushLine() {
            if (lineBuf.size() == 0) return
            val text = lineBuf.toString(StandardCharsets.UTF_8)
            lineBuf.reset()
            if (text.isBlank()) return
            if (capturing.get()) return
            onLine(text)
        }
    }
}
