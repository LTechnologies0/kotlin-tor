package org.kotlintor.hs

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.kotlintor.circuit.Circuit
import org.kotlintor.circuit.HopKeys
import org.kotlintor.circuit.TorStream
import org.kotlintor.circuit.ed25519IdLinkSpecifier
import org.kotlintor.circuit.ipv4LinkSpecifier
import org.kotlintor.circuit.legacyIdLinkSpecifier
import org.kotlintor.dir.Consensus
import org.kotlintor.dir.DescriptorParser
import org.kotlintor.dir.DirectoryClient
import org.kotlintor.dir.RouterStatus
import org.kotlintor.path.CircuitPath
import org.kotlintor.path.PathSelector
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat
import org.kotlintor.util.toHex
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

/**
 * Onion service v3 client: descriptor fetch, INTRODUCE1 / RENDEZVOUS2, and BEGIN on the
 * virtual HS hop.
 */
class OnionClient(
    private val dir: DirectoryClient,
    private val paths: PathSelector,
    private val buildCircuit: suspend (CircuitPath, Map<String, HopKeys>) -> Circuit,
    private val ensureHopKeys: suspend (String) -> HopKeys,
    private val identityCacheDir: Path? = null,
) {
    private val ed25519ByFp = HashMap<String, ByteArray>()
    private val cacheMutex = Mutex()

    data class FetchedDescriptor(
        val onionAddress: String,
        val outerText: String,
        val outer: HsDescriptorOuter,
        val inner: HsDescriptorInner,
        val blindedPublic: ByteArray,
        val period: HsTimePeriod,
    )

    /**
     * Fetch descriptor via BEGIN_DIR to a specific relay (debug / fallback when
     * the local consensus HSDir ring lags the publishers' ring).
     */
    suspend fun fetchDescriptorFromRelay(
        onionAddress: String,
        consensus: Consensus,
        hsdir: RouterStatus,
        period: HsTimePeriod = HsClient.timePeriodForConsensus(consensus),
    ): String {
        val identity = OnionAddressV3.decode(onionAddress)
        val blinded = HsKeyBlind.blindPublicKey(identity, period)
        val idB64 = Base64.getEncoder().withoutPadding().encodeToString(blinded)
        return fetchViaBeginDir(consensus, hsdir, idB64)
    }

    /**
     * Full client rendezvous: fetch descriptor → ESTABLISH_RENDEZVOUS → INTRODUCE1 →
     * RENDEZVOUS2 → BEGIN on the virtual hop.
     */
    suspend fun connect(onionAddress: String, port: Int, consensus: Consensus): TorStream {
        val fetched = fetchAndDecrypt(onionAddress, consensus)
        val identity = OnionAddressV3.decode(onionAddress)
        val subcred = HsKeyBlind.subcredential(identity, fetched.blindedPublic)
        require(fetched.inner.introductionPoints.isNotEmpty()) { "descriptor has no intro points" }

        var last: Exception? = null
        for (intro in fetched.inner.introductionPoints.shuffled()) {
            try {
                return connectViaIntro(fetched, intro, subcred, port, consensus)
            } catch (e: Exception) {
                last = e
                System.err.println("intro attempt failed: ${e.message}")
            }
        }
        throw IllegalStateException("all introduction points failed for $onionAddress", last)
    }

    private suspend fun connectViaIntro(
        fetched: FetchedDescriptor,
        intro: IntroductionPoint,
        subcred: ByteArray,
        port: Int,
        consensus: Consensus,
    ): TorStream {
        val links = LinkSpecifiers.parsePacked(intro.linkSpecifiers)
        val introFp = links.legacyId?.let { LinkSpecifiers.fingerprintHex(it) }
            ?: error("intro point missing legacy identity")
        val introRouter = consensus.relays.find { it.fingerprintHex == introFp }
            ?: RouterStatus(
                nickname = "Intro",
                identity = links.legacyId!!,
                digest = ByteArray(20),
                publication = consensus.validAfter,
                ip = links.ipv4?.let { InetAddress.getByAddress(it).hostAddress }
                    ?: error("intro point missing IPv4"),
                orPort = links.port ?: error("intro point missing ORPort"),
                dirPort = 0,
                flags = setOf("Running", "Fast", "V2Dir"),
                version = null,
                proto = emptyMap(),
                bandwidth = 1,
                ed25519Identity = links.ed25519Id,
            )

        // Rendezvous point: random Fast relay distinct from intro.
        val rendCandidates = consensus.relays.filter {
            it.isRunning && it.isFast && it.fingerprintHex != introFp
        }
        require(rendCandidates.isNotEmpty()) { "no rendezvous candidates" }
        val rend = rendCandidates[SecureRandomSource.nextInt(rendCandidates.size)]
        val rendKeys = ensureHopKeys(rend.fingerprintHex)

        println("HS rend=${rend.nickname} intro=${introRouter.nickname} ($introFp)")

        // Build rendezvous circuit first and ESTABLISH_RENDEZVOUS.
        val rendPath = paths.selectEndingAt(consensus.relays, rend)
        val rendHopKeys = mutableMapOf<String, HopKeys>()
        rendHopKeys[rendPath.guard.fingerprintHex] = ensureHopKeys(rendPath.guard.fingerprintHex)
        rendHopKeys[rendPath.middle.fingerprintHex] = ensureHopKeys(rendPath.middle.fingerprintHex)
        rendHopKeys[rendPath.exit.fingerprintHex] = rendKeys
        val rendCirc = buildCircuit(rendPath, rendHopKeys)
        val cookie = try {
            rendCirc.establishRendezvous()
        } catch (e: Exception) {
            rendCirc.close()
            throw e
        }

        val rendLinkSpecs = buildList {
            add(ipv4LinkSpecifier(InetAddress.getByName(rend.ip).address, rend.orPort))
            add(legacyIdLinkSpecifier(rend.identity))
            rendKeys.ed25519Identity?.let { add(ed25519IdLinkSpecifier(it)) }
        }

        val hsState = HsNtor.clientBegin(intro.encKeyNtor, intro.authKey, subcred)
        val plaintext = HsNtor.buildIntroducePlaintext(cookie, rendKeys.ntorOnionKey, rendLinkSpecs)
        val header = HsNtor.buildIntroHeader(intro.authKey)
        val encrypted = HsNtor.clientEncryptIntro(hsState, header, plaintext)
        val introducePayload = concat(header, encrypted)

        // Circuit to introduction point; send INTRODUCE1.
        val known = consensus.relays.mapTo(HashSet()) { it.fingerprintHex }
        val pathConsensusRelays =
            if (introFp in known) consensus.relays
            else consensus.relays + introRouter
        val introPath = paths.selectEndingAt(pathConsensusRelays, introRouter)
        val introHopKeys = mutableMapOf<String, HopKeys>()
        introHopKeys[introPath.guard.fingerprintHex] = ensureHopKeys(introPath.guard.fingerprintHex)
        introHopKeys[introPath.middle.fingerprintHex] = ensureHopKeys(introPath.middle.fingerprintHex)
        // Use descriptor onion-key for the intro-point hop when descriptor fetch didn't cache it.
        introHopKeys[introPath.exit.fingerprintHex] =
            HopKeys(intro.onionKeyNtor, links.ed25519Id ?: introRouter.ed25519Identity)
        val introCirc = try {
            buildCircuit(introPath, introHopKeys)
        } catch (e: Exception) {
            rendCirc.close()
            throw e
        }
        try {
            println("HS sending INTRODUCE1 (${introducePayload.size} bytes)…")
            introCirc.sendIntroduce1(introducePayload)
            println("HS INTRODUCE_ACK ok; waiting RENDEZVOUS2…")
        } finally {
            introCirc.close()
        }

        val handshake = try {
            rendCirc.awaitRendezvous2()
        } catch (e: Exception) {
            rendCirc.close()
            throw e
        }
        val hopKeys = HsNtor.clientFinishRendezvous(hsState, handshake)
        rendCirc.addHsHop(hopKeys)
        println("HS virtual hop established; BEGIN ${fetched.onionAddress}:$port")
        // BEGIN uses the onion hostname (or empty host with port) — Tor clients use the
        // .onion address string so the service can demux virtual ports.
        val host = fetched.onionAddress.removeSuffix(".onion").lowercase() + ".onion"
        return rendCirc.openStream(host, port)
    }

    suspend fun fetchAndDecrypt(onionAddress: String, consensus: Consensus): FetchedDescriptor {
        val identity = OnionAddressV3.decode(onionAddress)
        val outerText = fetchDescriptor(onionAddress, consensus)
        // Try current and previous periods for blinding used at publish time.
        val periods = listOf(
            HsClient.timePeriodForConsensus(consensus),
            HsClient.timePeriodForConsensus(consensus).let { it.copy(intervalNum = it.intervalNum - 1) },
        )
        var last: Exception? = null
        for (period in periods) {
            try {
                val blinded = HsKeyBlind.blindPublicKey(identity, period)
                val outer = HsDescriptorCodec.parseOuter(outerText)
                val inner = HsDescriptorCodec.decrypt(outer, identity, blinded)
                return FetchedDescriptor(onionAddress, outerText, outer, inner, blinded, period)
            } catch (e: Exception) {
                last = e
            }
        }
        throw IllegalStateException("HS descriptor decrypt failed", last)
    }

    suspend fun fetchDescriptor(onionAddress: String, consensus: Consensus): String {
        val identity = OnionAddressV3.decode(onionAddress)
        loadIdentityCache()
        val hsConsensuses = runCatching { dir.fetchMicrodescConsensusCandidates() }
            .getOrDefault(listOf(consensus))
            // Prefer older consensus first during rotation — descriptors often linger on the
            // previous HSDir ring after relays lose the HSDir flag in the newest vote.
            .sortedBy { it.validAfter }
        var last: Exception? = null
        for (hsConsensus in hsConsensuses) {
            println("HS enrich valid-after=${hsConsensus.validAfter}")
            enrichHsDirIdentities(hsConsensus)
            val enriched = hsConsensus.relays.map { r ->
                val ed = r.ed25519Identity ?: ed25519ByFp[r.fingerprintHex]
                if (ed != null && r.ed25519Identity == null) r.copy(ed25519Identity = ed) else r
            }
            val enrichedConsensus = hsConsensus.copy(relays = enriched)
            val known = consensus.relays.mapTo(HashSet()) { it.fingerprintHex }
            val pathConsensus = consensus.copy(
                relays = consensus.relays + enriched.filter { it.fingerprintHex !in known },
            )
            val hsdirCount = enriched.count { it.isHsDir && it.ed25519Identity != null }
            println("HS try consensus valid-after=${hsConsensus.validAfter} hsdirs=$hsdirCount")
            // Incomplete identity set warps the ring; skip until we have most HSDirs.
            val runningHs = enriched.count { it.isHsDir && it.isRunning }
            if (runningHs > 0 && hsdirCount < runningHs * 4 / 5) {
                println("HS skip ring: identities $hsdirCount/$runningHs incomplete")
                continue
            }
            val periods = listOf(HsClient.timePeriodForConsensus(hsConsensus))
            for (period in periods) {
                val blinded = HsKeyBlind.blindPublicKey(identity, period)
                val idB64 = Base64.getEncoder().withoutPadding().encodeToString(blinded)
                println("  period=${period.intervalNum} blinded=${blinded.toHex(8)}…")
                for (candidateSrv in HsClient.sharedRandomCandidates(hsConsensus, period)) {
                    val dirs = HsDirRing.selectFetchDirs(enrichedConsensus, blinded, period, candidateSrv)
                    if (dirs.isEmpty()) continue
                    println("  SRV=${candidateSrv.toHex(8)}… HSDirs=${dirs.map { it.nickname }}")
                    for (hsdir in dirs) {
                        try {
                            return fetchViaBeginDir(pathConsensus, hsdir, idB64)
                        } catch (e: Exception) {
                            last = e
                            println("  HSDir ${hsdir.nickname}: ${e.message}")
                        }
                    }
                }
            }
        }
        throw IllegalStateException("all HSDir descriptor fetches failed", last)
    }

    /**
     * Upload a signed outer HS descriptor to responsible HSDirs via BEGIN_DIR POST.
     * Returns the number of successful uploads.
     */
    suspend fun publishDescriptor(
        document: String,
        blindedPublic: ByteArray,
        consensus: Consensus,
    ): Int {
        loadIdentityCache()
        enrichHsDirIdentities(consensus)
        val enriched = consensus.relays.map { r ->
            val ed = r.ed25519Identity ?: ed25519ByFp[r.fingerprintHex]
            if (ed != null && r.ed25519Identity == null) r.copy(ed25519Identity = ed) else r
        }
        val enrichedConsensus = consensus.copy(relays = enriched)
        val period = HsClient.timePeriodForConsensus(consensus)
        val srv = HsClient.sharedRandomForUpload(consensus, period)
        val dirs = HsDirRing.selectStoreDirs(enrichedConsensus, blindedPublic, period, srv)
        check(dirs.isNotEmpty()) { "no HSDirs selected for store" }
        // C Tor uploads to the full store set; we stop early once a few succeed so
        // host bring-up isn't blocked by slow/dead HSDirs (still retries the ring).
        val wantOk = minOf(3, dirs.size)
        println("HS publish to ${dirs.size} HSDirs (period=${period.intervalNum}, want=$wantOk)")
        var ok = 0
        var last: Exception? = null
        for (hsdir in dirs) {
            try {
                postViaBeginDir(consensus, hsdir, document)
                ok++
                println("  HSDir ${hsdir.nickname}: uploaded")
                if (ok >= wantOk) break
            } catch (e: Exception) {
                last = e
                println("  HSDir ${hsdir.nickname}: ${e.message}")
            }
        }
        check(ok > 0) { "HS descriptor publish failed on all HSDirs" }
        return ok
    }

    private suspend fun postViaBeginDir(
        consensus: Consensus,
        hsdir: RouterStatus,
        document: String,
    ) {
        val path = paths.selectEndingAt(consensus.relays, hsdir)
        val keys = mutableMapOf<String, HopKeys>()
        keys[path.guard.fingerprintHex] = ensureHopKeys(path.guard.fingerprintHex)
        keys[path.middle.fingerprintHex] = ensureHopKeys(path.middle.fingerprintHex)
        keys[path.exit.fingerprintHex] = ensureHopKeys(path.exit.fingerprintHex)
        val circ = buildCircuit(path, keys)
        try {
            val stream = circ.openDirStream()
            try {
                val body = document.toByteArray()
                val req =
                    "POST /tor/hs/3/publish HTTP/1.0\r\n" +
                        "Host: hsdir\r\n" +
                        "User-Agent: kotlin-tor/0.1\r\n" +
                        "Content-Type: text/plain\r\n" +
                        "Content-Length: ${body.size}\r\n" +
                        "\r\n"
                stream.write(req.toByteArray() + body)
                val resp = stream.readHttpResponse()
                val text = resp.decodeToString()
                val code = Regex("^HTTP/1\\.\\d (\\d+)").find(text)?.groupValues?.get(1)?.toIntOrNull()
                    ?: error("no HTTP status in BEGIN_DIR publish response")
                if (code !in 200..299) {
                    val reason = text.lineSequence().firstOrNull()?.take(200)
                    val body = text.substringAfter("\r\n\r\n", "").take(200)
                    error("HS publish HTTP $code ($reason) $body")
                }
            } finally {
                runCatching { stream.close() }
            }
        } finally {
            circ.close()
        }
    }

    private suspend fun fetchViaBeginDir(
        consensus: Consensus,
        hsdir: RouterStatus,
        blindedIdB64: String,
    ): String {
        val path = paths.selectEndingAt(consensus.relays, hsdir)
        val keys = mutableMapOf<String, HopKeys>()
        keys[path.guard.fingerprintHex] = ensureHopKeys(path.guard.fingerprintHex)
        keys[path.middle.fingerprintHex] = ensureHopKeys(path.middle.fingerprintHex)
        keys[path.exit.fingerprintHex] = ensureHopKeys(path.exit.fingerprintHex)
        val circ = buildCircuit(path, keys)
        try {
            val stream = circ.openDirStream()
            try {
                val req =
                    "GET /tor/hs/3/$blindedIdB64 HTTP/1.0\r\n" +
                        "Host: hsdir\r\n" +
                        "User-Agent: kotlin-tor/0.1\r\n" +
                        "\r\n"
                stream.write(req.toByteArray())
                val resp = stream.readHttpResponse()
                val text = resp.decodeToString()
                val code = Regex("^HTTP/1\\.\\d (\\d+)").find(text)?.groupValues?.get(1)?.toIntOrNull()
                    ?: error("no HTTP status in BEGIN_DIR response")
                check(code in 200..299) { "HS descriptor HTTP $code" }
                val body = text.substringAfter("\r\n\r\n")
                check(body.contains("hs-descriptor") || body.contains("descriptor-signing-key-cert")) {
                    "response does not look like an HS descriptor (${body.take(80)})"
                }
                return body
            } finally {
                runCatching { stream.close() }
            }
        } finally {
            circ.close()
        }
    }

    private suspend fun enrichHsDirIdentities(consensus: Consensus) {
        val need = consensus.relays.filter {
            it.isHsDir && it.isRunning && it.fingerprintHex !in ed25519ByFp && it.ed25519Identity == null
        }
        if (need.isEmpty()) return
        println("fetching ed25519 identities for ${need.size} HSDirs…")
        coroutineScope {
            need.chunked(50).map { batch ->
                async(Dispatchers.IO) {
                    runCatching {
                        dir.fetchServerDescriptors(batch.map { it.fingerprintHex })
                    }.getOrDefault(emptyMap())
                }
            }.awaitAll().forEach { docs ->
                for ((fp, doc) in docs) {
                    DescriptorParser.parseEd25519Identity(doc)?.let {
                        ed25519ByFp[fp.uppercase()] = it
                    }
                }
            }
        }
        persistIdentityCache()
        println("HSDir identities cached=${ed25519ByFp.size}")
    }

    private suspend fun loadIdentityCache() = withContext(Dispatchers.IO) {
        val dirPath = identityCacheDir ?: return@withContext
        val file = dirPath.resolve("hsdir-ed25519.tsv")
        if (!Files.exists(file)) return@withContext
        cacheMutex.withLock {
            for (line in Files.readAllLines(file)) {
                val parts = line.split('\t')
                if (parts.size == 2) {
                    runCatching {
                        ed25519ByFp[parts[0].uppercase()] = Base64.getDecoder().decode(parts[1])
                    }
                }
            }
        }
    }

    private suspend fun persistIdentityCache() = withContext(Dispatchers.IO) {
        val dirPath = identityCacheDir ?: return@withContext
        Files.createDirectories(dirPath)
        val file = dirPath.resolve("hsdir-ed25519.tsv")
        cacheMutex.withLock {
            val body = ed25519ByFp.entries.joinToString("\n") { (fp, ed) ->
                "$fp\t${Base64.getEncoder().encodeToString(ed)}"
            }
            Files.writeString(file, body)
        }
    }
}
