package org.kotlintor.net.stack

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kotlintor.net.BytePipe
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

/**
 * Pure-Kotlin userspace IPv4 L3/L4 stack for TUN ↔ Tor.
 *
 * Device writes IP packets into [inject]; stack emits reply packets via [emit].
 * TCP flows open remote streams through [openTcp] (typically TorClient.connect → BytePipe).
 * UDP datagrams are handed to [onUdp] (DNSPort / UdpOverTcp / drop).
 * ICMP Echo Request is answered locally.
 */
class TunIpStack(
    internal val scope: CoroutineScope,
    private val emit: suspend (ByteArray) -> Unit,
    private val openTcp: suspend (dstIp: String, dstPort: Int) -> BytePipe,
    private val onUdp: (suspend (srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, payload: ByteArray) -> Unit)? = null,
) {
    private val flows = ConcurrentHashMap<FlowKey, TcpFlow>()
    private val ipId = AtomicInteger(Random.nextInt() and 0xffff)
    private val mutex = Mutex()

    data class FlowKey(val cIp: String, val cPort: Int, val sIp: String, val sPort: Int)

    suspend fun inject(packet: ByteArray) {
        val ip = Ipv4Packet.parse(packet) ?: return
        when (ip.protocol) {
            Ipv4Packet.PROTO_ICMP -> handleIcmp(ip)
            Ipv4Packet.PROTO_UDP -> handleUdp(ip)
            Ipv4Packet.PROTO_TCP -> handleTcp(ip)
        }
    }

    fun activeTcpFlows(): Int = flows.size

    private suspend fun handleIcmp(ip: Ipv4Packet.Packet) {
        val echo = IcmpEcho.parse(ip.payload) ?: return
        if (echo.type != IcmpEcho.TYPE_ECHO_REQUEST) return
        val reply = IcmpEcho.buildEchoReply(echo)
        val out = Ipv4Packet.build(
            src = ip.dst,
            dst = ip.src,
            protocol = Ipv4Packet.PROTO_ICMP,
            payload = reply,
            identification = ipId.getAndIncrement() and 0xffff,
        )
        emit(out)
    }

    private suspend fun handleUdp(ip: Ipv4Packet.Packet) {
        val udp = UdpDatagram.parse(ip.payload) ?: return
        onUdp?.invoke(ip.src, udp.srcPort, ip.dst, udp.dstPort, udp.payload)
    }

    /** Inject a UDP reply toward the TUN client. */
    suspend fun sendUdp(
        srcIp: ByteArray,
        srcPort: Int,
        dstIp: ByteArray,
        dstPort: Int,
        payload: ByteArray,
    ) {
        val udp = UdpDatagram.build(srcIp, dstIp, srcPort, dstPort, payload)
        emit(
            Ipv4Packet.build(
                src = srcIp,
                dst = dstIp,
                protocol = Ipv4Packet.PROTO_UDP,
                payload = udp,
                identification = ipId.getAndIncrement() and 0xffff,
            ),
        )
    }

    private suspend fun handleTcp(ip: Ipv4Packet.Packet) {
        val seg = TcpSegment.parse(ip.payload) ?: return
        val key = FlowKey(ip.srcString(), seg.srcPort, ip.dstString(), seg.dstPort)
        if (seg.rst) {
            flows.remove(key)?.close()
            return
        }
        if (seg.syn && !seg.ackFlag) {
            mutex.withLock {
                if (flows.containsKey(key)) return
                val flow = TcpFlow(this, key, ip.src.copyOf(), ip.dst.copyOf(), seg)
                flows[key] = flow
                scope.launch { flow.runHandshakeAndBridge(openTcp) }
            }
            return
        }
        flows[key]?.onSegment(seg)
    }

    internal suspend fun emitTcp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
    ) {
        val tcp = TcpSegment.build(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload = payload)
        emit(
            Ipv4Packet.build(
                src = srcIp,
                dst = dstIp,
                protocol = Ipv4Packet.PROTO_TCP,
                payload = tcp,
                identification = ipId.getAndIncrement() and 0xffff,
            ),
        )
    }

    internal fun removeFlow(key: FlowKey) {
        flows.remove(key)
    }
}

internal class TcpFlow(
    private val stack: TunIpStack,
    private val key: TunIpStack.FlowKey,
    private val clientIp: ByteArray,
    private val serverIp: ByteArray,
    syn: org.kotlintor.net.TcpHeader.Segment,
) {
    private val clientPort = syn.srcPort
    private val serverPort = syn.dstPort
    private val iss = AtomicLong((Random.nextInt().toLong() and 0xffffffffL))
    private var sndNxt = iss.get()
    private var rcvNxt = (syn.seq + 1) and 0xffffffffL
    private val inbound = Channel<org.kotlintor.net.TcpHeader.Segment>(Channel.BUFFERED)
    private var pipe: BytePipe? = null
    private val closed = AtomicInteger(0)

    suspend fun runHandshakeAndBridge(openTcp: suspend (String, Int) -> BytePipe) {
        // SYN-ACK
        sndNxt = (iss.get() + 1) and 0xffffffffL
        stack.emitTcp(
            srcIp = serverIp,
            dstIp = clientIp,
            srcPort = serverPort,
            dstPort = clientPort,
            seq = iss.get(),
            ack = rcvNxt,
            flags = TcpSegment.FLAG_SYN or TcpSegment.FLAG_ACK,
        )
        try {
            val remote = openTcp(key.sIp, key.sPort)
            pipe = remote
            // wait for ACK completing handshake (and any early data)
            val first = inbound.receive()
            if (first.rst) {
                close()
                return
            }
            if (first.ackFlag) {
                // established
            }
            if (first.payload.isNotEmpty()) {
                rcvNxt = (rcvNxt + first.payload.size) and 0xffffffffL
                remote.write(first.payload)
                stack.emitTcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, TcpSegment.FLAG_ACK)
            }
            kotlinx.coroutines.coroutineScope {
                val up = launch {
                    val buf = ByteArray(16 * 1024)
                    while (closed.get() == 0) {
                        val n = remote.read(buf)
                        if (n < 0) break
                        if (n == 0) continue
                        val chunk = buf.copyOf(n)
                        stack.emitTcp(
                            serverIp, clientIp, serverPort, clientPort,
                            sndNxt, rcvNxt,
                            TcpSegment.FLAG_ACK or TcpSegment.FLAG_PSH,
                            chunk,
                        )
                        sndNxt = (sndNxt + n) and 0xffffffffL
                    }
                    // FIN toward client
                    stack.emitTcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, TcpSegment.FLAG_FIN or TcpSegment.FLAG_ACK)
                    sndNxt = (sndNxt + 1) and 0xffffffffL
                }
                try {
                    while (closed.get() == 0) {
                        val seg = inbound.receive()
                        if (seg.rst) break
                        if (seg.payload.isNotEmpty()) {
                            rcvNxt = (rcvNxt + seg.payload.size) and 0xffffffffL
                            remote.write(seg.payload)
                            stack.emitTcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, TcpSegment.FLAG_ACK)
                        }
                        if (seg.fin) {
                            rcvNxt = (rcvNxt + 1) and 0xffffffffL
                            stack.emitTcp(serverIp, clientIp, serverPort, clientPort, sndNxt, rcvNxt, TcpSegment.FLAG_ACK)
                            break
                        }
                    }
                } finally {
                    up.cancel()
                }
            }
        } catch (_: Exception) {
            runCatching {
                stack.emitTcp(
                    serverIp, clientIp, serverPort, clientPort,
                    sndNxt, rcvNxt, TcpSegment.FLAG_RST or TcpSegment.FLAG_ACK,
                )
            }
        } finally {
            close()
        }
    }

    suspend fun onSegment(seg: org.kotlintor.net.TcpHeader.Segment) {
        inbound.send(seg)
    }

    fun close() {
        if (closed.getAndSet(1) != 0) return
        inbound.close()
        val p = pipe
        pipe = null
        if (p != null) {
            stack.scope.launch {
                runCatching { p.close() }
            }
        }
        stack.removeFlow(key)
    }
}
