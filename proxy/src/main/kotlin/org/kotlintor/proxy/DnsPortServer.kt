package org.kotlintor.proxy

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import org.kotlintor.TorClient
import org.kotlintor.config.ListenSpec
import org.kotlintor.link.ConnectionTable
import org.kotlintor.link.ConnectionType
import org.kotlintor.link.ListenerConnection
import org.kotlintor.net.ExitDialer
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer

/**
 * DNSPort: UDP DNS → [ExitDialer.resolve] (Tor RELAY RESOLVE or DNSSEC stub).
 * On DNSSEC failure responds SERVFAIL; on Secure success sets AD=1.
 */
class DnsPortServer(
    private val dialer: ExitDialer,
    private val scope: CoroutineScope,
    private val maxInFlight: Int = ProxyAcceptLimits.DEFAULT_DNS,
    private val dnssecEnabled: Boolean = false,
) {
    constructor(
        client: TorClient,
        scope: CoroutineScope,
        maxInFlight: Int = ProxyAcceptLimits.DEFAULT_DNS,
    ) : this(
        dialer = TorClientDialer(client),
        scope = scope,
        maxInFlight = maxInFlight,
        dnssecEnabled = client.dnssecValidate,
    )

    private var job: Job? = null
    private var socket: DatagramSocket? = null
    private var listenerHandle: ListenerConnection? = null
    private val gate: Semaphore = ProxyAcceptLimits.semaphore(maxInFlight)

    fun start(listen: ListenSpec) {
        job = scope.launch(Dispatchers.IO) {
            val ds = DatagramSocket(null)
            ds.bind(InetSocketAddress(listen.host, if (listen.port == 0) 0 else listen.port))
            socket = ds
            val lh = ConnectionTable.newListener(listen.host, ds.localPort, ConnectionType.AP)
            lh.markOpen()
            listenerHandle = lh
            val buf = ByteArray(512)
            while (isActive) {
                val packet = DatagramPacket(buf, buf.size)
                runCatching { ds.receive(packet) }.getOrNull() ?: break
                if (!gate.tryAcquire()) continue
                val payload = packet.data.copyOf(packet.length)
                val from = packet.address
                val port = packet.port
                launch {
                    try {
                        handleQuery(ds, payload, from, port)
                    } finally {
                        gate.release()
                    }
                }
            }
        }
    }

    fun boundPort(): Int = socket?.localPort ?: -1

    fun stop() {
        runCatching { socket?.close() }
        job?.cancel()
        listenerHandle?.let {
            it.markClosed()
            ConnectionTable.remove(it.id)
        }
        listenerHandle = null
    }

    private suspend fun handleQuery(ds: DatagramSocket, raw: ByteArray, from: InetAddress, port: Int) {
        try {
            if (raw.size < 12) return
            // Ignore responses (QR=1) — only answer queries.
            if ((raw[2].toInt() and 0x80) != 0) return
            val parsed = parseQuery(raw) ?: return
            val qname = parsed.first
            val qtype = parsed.second
            val outcome = runCatching {
                val addrs = dialer.resolve(qname)
                true to addrs
            }.getOrElse { false to emptyList() }
            val (ok, addrs) = outcome
            val resp = when {
                !ok && dnssecEnabled -> buildServfail(raw)
                !ok || addrs.isEmpty() -> buildNxdomain(raw)
                else -> buildResponse(raw, addrs, qtype, authenticated = dnssecEnabled)
            }
            ds.send(DatagramPacket(resp, resp.size, from, port))
        } catch (_: Exception) {
            if (dnssecEnabled) {
                runCatching {
                    val resp = buildServfail(raw)
                    ds.send(DatagramPacket(resp, resp.size, from, port))
                }
            }
        }
    }

    /** @return qname to QTYPE, or null */
    private fun parseQuery(raw: ByteArray): Pair<String, Int>? {
        if (raw.size < 12) return null
        var i = 12
        val labels = mutableListOf<String>()
        while (i < raw.size) {
            val len = raw[i].toInt() and 0xff
            if (len == 0) break
            if (len and 0xc0 != 0) return null
            i++
            if (i + len > raw.size) return null
            labels += raw.copyOfRange(i, i + len).toString(Charsets.US_ASCII)
            i += len
        }
        if (i >= raw.size) return null
        i++ // skip 0
        if (i + 4 > raw.size) return null
        val qtype = ((raw[i].toInt() and 0xff) shl 8) or (raw[i + 1].toInt() and 0xff)
        val qname = labels.joinToString(".").ifEmpty { return null }
        return qname to qtype
    }

    private fun buildServfail(query: ByteArray): ByteArray {
        val out = ByteBuffer.allocate(512)
        if (query.size >= 12) {
            out.put(query, 0, 2)
            // QR=1, RA copy RD, RCODE=SERVFAIL(2)
            val flagsHi = ((query[2].toInt() and 0xff) or 0x80)
            val flagsLo = (query[3].toInt() and 0xff and 0xf0) or 0x02
            out.put(flagsHi.toByte())
            out.put(flagsLo.toByte())
            out.putShort(1)
            out.putShort(0)
            out.putShort(0)
            out.putShort(0)
            var i = 12
            while (i < query.size && query[i].toInt() != 0) {
                val len = query[i].toInt() and 0xff
                out.put(query, i, 1 + len)
                i += 1 + len
            }
            if (i < query.size) {
                out.put(0)
                i++
                if (i + 4 <= query.size) out.put(query, i, 4)
            }
        }
        return out.array().copyOf(out.position())
    }

    private fun buildNxdomain(query: ByteArray): ByteArray {
        val out = ByteBuffer.allocate(512)
        if (query.size >= 12) {
            out.put(query, 0, 2)
            val flagsHi = ((query[2].toInt() and 0xff) or 0x80)
            val flagsLo = (query[3].toInt() and 0xff and 0xf0) or 0x03 // NXDOMAIN
            out.put(flagsHi.toByte())
            out.put(flagsLo.toByte())
            out.putShort(1)
            out.putShort(0)
            out.putShort(0)
            out.putShort(0)
            copyQuestion(query, out)
        }
        return out.array().copyOf(out.position())
    }

    private fun buildResponse(
        query: ByteArray,
        addrs: List<String>,
        qtype: Int,
        authenticated: Boolean,
    ): ByteArray {
        val out = ByteBuffer.allocate(512)
        if (query.size >= 12) {
            out.put(query, 0, 2)
            out.put(((query[2].toInt() and 0xff) or 0x80).toByte())
            var flagsLo = 0x00
            if (authenticated) flagsLo = flagsLo or 0x20
            out.put(flagsLo.toByte())
            out.putShort(1)
            val wanted = when (qtype) {
                1 -> addrs.filter { it.contains('.') && !it.contains(':') }
                28 -> addrs.filter { it.contains(':') }
                else -> emptyList()
            }.take(8)
            out.putShort(wanted.size.toShort())
            out.putShort(0); out.putShort(0)
            copyQuestion(query, out)
            var written = 0
            for (a in wanted) {
                if (written >= 8) break
                when (qtype) {
                    1 -> {
                        val parts = a.split('.')
                        if (parts.size != 4) continue
                        out.put(0xc0.toByte()); out.put(0x0c)
                        out.putShort(1)
                        out.putShort(1)
                        out.putInt(60)
                        out.putShort(4)
                        for (p in parts) out.put(p.toInt().toByte())
                        written++
                    }
                    28 -> {
                        val bytes = runCatching { InetAddress.getByName(a).address }.getOrNull()
                            ?: continue
                        if (bytes.size != 16) continue
                        out.put(0xc0.toByte()); out.put(0x0c)
                        out.putShort(28)
                        out.putShort(1)
                        out.putInt(60)
                        out.putShort(16)
                        out.put(bytes)
                        written++
                    }
                }
            }
        }
        return out.array().copyOf(out.position())
    }

    private fun copyQuestion(query: ByteArray, out: ByteBuffer) {
        var i = 12
        while (i < query.size && query[i].toInt() != 0) {
            val len = query[i].toInt() and 0xff
            out.put(query, i, 1 + len)
            i += 1 + len
        }
        if (i < query.size) {
            out.put(0)
            i++
            if (i + 4 <= query.size) out.put(query, i, 4)
        }
    }
}
