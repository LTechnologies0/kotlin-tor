package org.kotlintor.net.stack

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kotlintor.net.BytePipe
import java.io.InputStream
import java.io.OutputStream

/**
 * Raw packet I/O for a TUN device (or test harness).
 * Android: wrap ParcelFileDescriptor streams; tests: MemoryTun.
 */
interface PacketIo {
    /** Read one IP packet; return null on EOF. */
    suspend fun readPacket(buf: ByteArray): Int?
    suspend fun writePacket(packet: ByteArray)
    fun close()
}

/** Stream-based PacketIo (Linux TUN / Android VpnService fd). */
class StreamPacketIo(
    private val input: InputStream,
    private val output: OutputStream,
) : PacketIo {
    private val writeMutex = Mutex()

    override suspend fun readPacket(buf: ByteArray): Int? =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val n = input.read(buf)
            if (n < 0) null else n
        }

    override suspend fun writePacket(packet: ByteArray) {
        writeMutex.withLock {
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                output.write(packet)
                output.flush()
            }
        }
    }

    override fun close() {
        runCatching { input.close() }
        runCatching { output.close() }
    }
}

/**
 * Pumps TUN ↔ [TunIpStack] ↔ Tor TCP.
 *
 * [openTcp] should protect the uplink socket (VpnService.protect) before dialing Tor.
 */
class TunTorBridge(
    private val scope: CoroutineScope,
    private val io: PacketIo,
    openTcp: suspend (dstIp: String, dstPort: Int) -> BytePipe,
    onUdp: (suspend (srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, payload: ByteArray) -> Unit)? = null,
    private val mtu: Int = 1500,
) {
    private val stack = TunIpStack(
        scope = scope,
        emit = { pkt -> io.writePacket(pkt) },
        openTcp = openTcp,
        onUdp = onUdp,
    )
    private var job: Job? = null

    val ipStack: TunIpStack get() = stack

    fun start() {
        if (job != null) return
        job = scope.launch {
            val buf = ByteArray(mtu.coerceAtLeast(1500) + 64)
            while (isActive) {
                val n = io.readPacket(buf) ?: break
                if (n <= 0) continue
                // Android sometimes prefixes 4-byte tun PI; detect IPv4 version nibble.
                val offset = when {
                    n >= 4 && ((buf[0].toInt() ushr 4) and 0x0f) == 4 -> 0
                    n >= 8 && ((buf[4].toInt() ushr 4) and 0x0f) == 4 -> 4
                    else -> 0
                }
                if (n - offset < 20) continue
                val pkt = buf.copyOfRange(offset, n)
                runCatching { stack.inject(pkt) }
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        io.close()
    }
}

/** In-memory TUN for unit tests: bidirectional packet queues. */
class MemoryTun : PacketIo {
    private val inbound = kotlinx.coroutines.channels.Channel<ByteArray>(kotlinx.coroutines.channels.Channel.BUFFERED)
    private val outbound = kotlinx.coroutines.channels.Channel<ByteArray>(kotlinx.coroutines.channels.Channel.BUFFERED)

    suspend fun injectFromDevice(packet: ByteArray) = inbound.send(packet)
    suspend fun takeEmitted(): ByteArray = outbound.receive()

    override suspend fun readPacket(buf: ByteArray): Int? {
        val pkt = inbound.receiveCatching().getOrNull() ?: return null
        System.arraycopy(pkt, 0, buf, 0, pkt.size.coerceAtMost(buf.size))
        return pkt.size.coerceAtMost(buf.size)
    }

    override suspend fun writePacket(packet: ByteArray) {
        outbound.send(packet.copyOf())
    }

    override fun close() {
        inbound.close()
        outbound.close()
    }
}
