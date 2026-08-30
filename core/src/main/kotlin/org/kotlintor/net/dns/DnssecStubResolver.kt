package org.kotlintor.net.dns

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kotlintor.net.BytePipe
import org.kotlintor.net.DnsTcpFraming

/**
 * Fail-closed DNSSEC validating stub over Tor TCP/53 to a recursive resolver.
 * Does not trust the AD bit alone — locally validates RRSIG chains to [TrustAnchors].
 */
class DnssecStubResolver(
    private val recursiveHost: String,
    private val recursivePort: Int = 53,
    private val trustAnchors: List<TrustAnchor> = TrustAnchors.defaultRoot(),
    private val openPipe: suspend (host: String, port: Int) -> BytePipe,
    private val timeoutMs: Int = 15_000,
) {
    private val validator = DnssecValidator(trustAnchors)

    class DnssecResolveException(message: String) : Exception(message)

    /**
     * Resolve [hostname] to A/AAAA strings. Throws [DnssecResolveException] on
     * insecure/bogus/indeterminate outcomes (fail closed).
     */
    suspend fun resolve(hostname: String): List<String> = withContext(Dispatchers.IO) {
        val name = DnsMessage.canonicalizeName(hostname)
        if (name.isEmpty()) throw DnssecResolveException("empty name")

        val addrs = ArrayList<String>()
        resolveType(name, DnsTypes.A, addrs)
        resolveType(name, DnsTypes.AAAA, addrs)
        if (addrs.isEmpty()) {
            throw DnssecResolveException("no validated A/AAAA for $name")
        }
        addrs.distinct()
    }

    private suspend fun resolveType(name: String, type: Int, out: MutableList<String>) {
        val packet = query(name, type)
        if (packet.rcode == 3) return
        if (packet.rcode != 0) {
            throw DnssecResolveException("rcode=${packet.rcode} for $name type=$type")
        }
        val answers = packet.answers.filter {
            DnsMessage.canonicalizeName(it.name) == name && it.type == type
        }
        if (answers.isEmpty()) return

        val sigs = packet.answers
            .filter {
                DnsMessage.canonicalizeName(it.name) == name && it.type == DnsTypes.RRSIG
            }
            .mapNotNull { runCatching { RrsigRdata.parse(it.rdata) }.getOrNull() }
            .filter { it.typeCovered == type }
        if (sigs.isEmpty()) {
            throw DnssecResolveException("insecure (no RRSIG) for $name type=$type")
        }

        val signer = DnsMessage.canonicalizeName(sigs.first().signerName)
        val dnskeyByZone = LinkedHashMap<String, List<DnsRr>>()
        val dsByZone = LinkedHashMap<String, List<DnsRr>>()
        ensureZoneChain(signer, dnskeyByZone, dsByZone)

        val result = validator.validateAnswer(
            qname = name,
            qtype = type,
            answerRecords = answers,
            answerRrsigs = sigs,
            dnskeyByZone = dnskeyByZone,
            dsByZone = dsByZone,
        )
        when (result.status) {
            DnssecStatus.SECURE -> {
                for (rr in answers) {
                    when (type) {
                        DnsTypes.A -> out += DnsMessage.parseA(rr.rdata)
                        DnsTypes.AAAA -> out += DnsMessage.parseAaaa(rr.rdata)
                    }
                }
            }
            DnssecStatus.INSECURE ->
                throw DnssecResolveException("insecure answer for $name type=$type")
            DnssecStatus.BOGUS, DnssecStatus.INDETERMINATE ->
                throw DnssecResolveException("${result.status}: ${result.reason}")
        }
    }

    private suspend fun ensureZoneChain(
        signerZone: String,
        dnskeyByZone: MutableMap<String, List<DnsRr>>,
        dsByZone: MutableMap<String, List<DnsRr>>,
    ) {
        val chain = validator.zoneChain(signerZone)
        for (i in chain.indices) {
            val cut = chain[i]
            if (i > 0) fetchAndStoreDs(cut, dsByZone)
            fetchAndStoreDnskey(cut, dnskeyByZone)
        }
    }

    private suspend fun fetchAndStoreDnskey(
        zone: String,
        dnskeyByZone: MutableMap<String, List<DnsRr>>,
    ) {
        val qname = if (zone.isEmpty()) "." else zone
        val packet = query(qname, DnsTypes.DNSKEY)
        if (packet.rcode != 0) throw DnssecResolveException("DNSKEY query failed for $zone")
        val owner = DnsMessage.canonicalizeName(zone)
        val keys = packet.answers.filter {
            DnsMessage.canonicalizeName(it.name) == owner && it.type == DnsTypes.DNSKEY
        }
        if (keys.isEmpty()) throw DnssecResolveException("no DNSKEY for $zone")
        val sigs = packet.answers.filter {
            DnsMessage.canonicalizeName(it.name) == owner && it.type == DnsTypes.RRSIG
        }.filter {
            runCatching { RrsigRdata.parse(it.rdata).typeCovered }.getOrNull() == DnsTypes.DNSKEY
        }
        dnskeyByZone[owner] = keys
        dnskeyByZone["$owner|rrsig|${DnsTypes.DNSKEY}"] = sigs
    }

    private suspend fun fetchAndStoreDs(
        childZone: String,
        dsByZone: MutableMap<String, List<DnsRr>>,
    ) {
        val packet = query(childZone, DnsTypes.DS)
        if (packet.rcode != 0) throw DnssecResolveException("DS query failed for $childZone")
        val owner = DnsMessage.canonicalizeName(childZone)
        val ds = packet.answers.filter {
            DnsMessage.canonicalizeName(it.name) == owner && it.type == DnsTypes.DS
        }
        if (ds.isEmpty()) {
            throw DnssecResolveException("insecure delegation (no DS) for $childZone")
        }
        val sigs = packet.answers.filter {
            DnsMessage.canonicalizeName(it.name) == owner && it.type == DnsTypes.RRSIG
        }.filter {
            runCatching { RrsigRdata.parse(it.rdata).typeCovered }.getOrNull() == DnsTypes.DS
        }
        dsByZone[owner] = ds
        dsByZone["$owner|rrsig|${DnsTypes.DS}"] = sigs
    }

    private suspend fun query(qname: String, qtype: Int): DnsPacket {
        val msg = DnsMessage.buildQuery(qname = qname, qtype = qtype, dnssecOk = true)
        val expectedId = ((msg[0].toInt() and 0xff) shl 8) or (msg[1].toInt() and 0xff)
        val pipe = openPipe(recursiveHost, recursivePort)
        try {
            pipe.write(DnsTcpFraming.encode(msg))
            val body = readTcpDnsMessage(pipe)
            val packet = DnsMessage.parse(body)
            if (packet.id != expectedId) {
                throw DnssecResolveException("DNS id mismatch")
            }
            return packet
        } finally {
            runCatching { pipe.close() }
        }
    }

    private suspend fun readTcpDnsMessage(pipe: BytePipe): ByteArray {
        val hdr = ByteArray(2)
        readFully(pipe, hdr)
        val len = ((hdr[0].toInt() and 0xff) shl 8) or (hdr[1].toInt() and 0xff)
        if (len <= 0 || len > 65535) throw DnssecResolveException("bad TCP DNS length")
        val body = ByteArray(len)
        readFully(pipe, body)
        return body
    }

    private suspend fun readFully(pipe: BytePipe, dst: ByteArray) {
        var off = 0
        while (off < dst.size) {
            val n = pipe.read(dst, off, dst.size - off)
            if (n < 0) throw DnssecResolveException("TCP DNS EOF")
            off += n
        }
    }
}

/** Parse host:port for DNSSECRecursive. */
fun parseRecursiveEndpoint(spec: String, defaultPort: Int = 53): Pair<String, Int> {
    val t = spec.trim()
    if (t.startsWith("[")) {
        val end = t.indexOf(']')
        require(end > 0) { "bad IPv6 recursive $spec" }
        val host = t.substring(1, end)
        val rest = t.substring(end + 1)
        val port = if (rest.startsWith(":")) rest.drop(1).toInt() else defaultPort
        return host to port
    }
    val idx = t.lastIndexOf(':')
    return if (idx > 0 && t.indexOf(':') == idx) {
        t.substring(0, idx) to t.substring(idx + 1).toInt()
    } else {
        t to defaultPort
    }
}
