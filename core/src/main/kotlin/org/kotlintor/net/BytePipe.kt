package org.kotlintor.net

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Duplex byte pipe with pause / rate / counters — the unit of Tor proxy forwarding.
 *
 * Kernel TCP is only used as a local carrier ([fromSocket]); all protocol bytes and
 * Tor-side RELAY DATA are shaped through this API in pure Kotlin.
 */
interface BytePipe {
    suspend fun read(dst: ByteArray, offset: Int = 0, length: Int = dst.size): Int
    suspend fun write(src: ByteArray, offset: Int = 0, length: Int = src.size)
    suspend fun write(src: ByteArray) = write(src, 0, src.size)
    fun isClosed(): Boolean
    suspend fun close()

    val bytesRead: Long
    val bytesWritten: Long
}

/**
 * Token-bucket shaper applied around any [BytePipe].
 * @param bytesPerSecond 0 = unlimited
 */
class StreamShaper(
    private val inner: BytePipe,
    private val bytesPerSecond: Long = 0,
) : BytePipe by inner {
    private val mutex = Mutex()
    private var tokens = bytesPerSecond.toDouble()
    private var lastNs = System.nanoTime()
    private val paused = AtomicBoolean(false)

    fun pause() { paused.set(true) }
    fun resume() { paused.set(false) }
    fun isPaused(): Boolean = paused.get()

    override suspend fun read(dst: ByteArray, offset: Int, length: Int): Int {
        awaitUnpaused()
        val n = inner.read(dst, offset, length)
        if (n > 0) take(n)
        return n
    }

    override suspend fun write(src: ByteArray, offset: Int, length: Int) {
        awaitUnpaused()
        take(length)
        inner.write(src, offset, length)
    }

    private suspend fun awaitUnpaused() {
        while (paused.get()) {
            kotlinx.coroutines.delay(5)
        }
    }

    private suspend fun take(n: Int) {
        if (bytesPerSecond <= 0 || n <= 0) return
        mutex.withLock {
            while (true) {
                refillLocked()
                if (tokens >= n) {
                    tokens -= n
                    return
                }
                val need = n - tokens
                val waitMs = ((need * 1000.0) / bytesPerSecond).toLong().coerceAtLeast(1)
                kotlinx.coroutines.delay(waitMs)
            }
        }
    }

    private fun refillLocked() {
        val now = System.nanoTime()
        val elapsed = (now - lastNs) / 1_000_000_000.0
        lastNs = now
        tokens = (tokens + elapsed * bytesPerSecond).coerceAtMost(bytesPerSecond * 2.0)
    }
}

/** In-memory pipe pair for tests / encapsulation demos. */
class MemoryBytePipe : BytePipe {
    private val ch = Channel<ByteArray>(Channel.UNLIMITED)
    private val closed = AtomicBoolean(false)
    private val _read = AtomicLong(0)
    private val _write = AtomicLong(0)
    private var leftover: ByteArray = ByteArray(0)
    private var leftoverPos = 0

    override val bytesRead: Long get() = _read.get()
    override val bytesWritten: Long get() = _write.get()

    override fun isClosed(): Boolean = closed.get()

    override suspend fun read(dst: ByteArray, offset: Int, length: Int): Int {
        if (closed.get() && leftoverPos >= leftover.size) {
            val next = ch.tryReceive().getOrNull()
            if (next == null) return -1
            leftover = next
            leftoverPos = 0
        }
        if (leftoverPos < leftover.size) {
            val n = minOf(length, leftover.size - leftoverPos)
            System.arraycopy(leftover, leftoverPos, dst, offset, n)
            leftoverPos += n
            _read.addAndGet(n.toLong())
            return n
        }
        val chunk = ch.receiveCatching().getOrNull() ?: return -1
        leftover = chunk
        leftoverPos = 0
        return read(dst, offset, length)
    }

    override suspend fun write(src: ByteArray, offset: Int, length: Int) {
        check(!closed.get()) { "pipe closed" }
        if (length <= 0) return
        val copy = src.copyOfRange(offset, offset + length)
        ch.send(copy)
        _write.addAndGet(length.toLong())
    }

    override suspend fun close() {
        if (closed.compareAndSet(false, true)) ch.close()
    }
}

/** Blocking socket adapted to [BytePipe] (local accept side). */
class SocketBytePipe(private val socket: Socket) : BytePipe {
    private val input: InputStream = socket.getInputStream()
    private val output: OutputStream = socket.getOutputStream()
    private val closed = AtomicBoolean(false)
    private val _read = AtomicLong(0)
    private val _write = AtomicLong(0)

    override val bytesRead: Long get() = _read.get()
    override val bytesWritten: Long get() = _write.get()

    override fun isClosed(): Boolean = closed.get() || socket.isClosed

    override suspend fun read(dst: ByteArray, offset: Int, length: Int): Int =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val n = input.read(dst, offset, length)
            if (n > 0) _read.addAndGet(n.toLong())
            n
        }

    override suspend fun write(src: ByteArray, offset: Int, length: Int) {
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            output.write(src, offset, length)
            output.flush()
            _write.addAndGet(length.toLong())
        }
    }

    override suspend fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { socket.close() }
        }
    }
}

/**
 * Adapts [org.kotlintor.circuit.TorStream] RELAY DATA cells to [BytePipe].
 */
class TorStreamBytePipe(
    private val stream: org.kotlintor.circuit.TorStream,
) : BytePipe {
    private val closed = AtomicBoolean(false)
    private val _read = AtomicLong(0)
    private val _write = AtomicLong(0)
    private var leftover: ByteArray = ByteArray(0)
    private var leftoverPos = 0

    override val bytesRead: Long get() = _read.get()
    override val bytesWritten: Long get() = _write.get()

    override fun isClosed(): Boolean = closed.get()

    override suspend fun read(dst: ByteArray, offset: Int, length: Int): Int {
        if (closed.get()) return -1
        if (leftoverPos < leftover.size) {
            val n = minOf(length, leftover.size - leftoverPos)
            System.arraycopy(leftover, leftoverPos, dst, offset, n)
            leftoverPos += n
            _read.addAndGet(n.toLong())
            return n
        }
        val chunk = stream.read()
        if (chunk.isEmpty()) {
            closed.set(true)
            return -1
        }
        leftover = chunk
        leftoverPos = 0
        return read(dst, offset, length)
    }

    override suspend fun write(src: ByteArray, offset: Int, length: Int) {
        check(!closed.get()) { "tor stream closed" }
        if (length <= 0) return
        stream.write(src.copyOfRange(offset, offset + length))
        _write.addAndGet(length.toLong())
    }

    override suspend fun close() {
        if (closed.compareAndSet(false, true)) {
            runCatching { stream.close() }
        }
    }
}
