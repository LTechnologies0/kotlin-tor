package org.kotlintor

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kotlintor.circuit.Circuit
import org.kotlintor.circuit.CircuitManager
import org.kotlintor.circuit.HopKeys
import org.kotlintor.circuit.TorStream
import org.kotlintor.config.IsolationFlag
import org.kotlintor.config.TorConfig
import org.kotlintor.dir.Consensus
import org.kotlintor.dir.DescriptorParser
import org.kotlintor.dir.DirectoryClient
import org.kotlintor.dir.RouterStatus
import org.kotlintor.hs.HsClient
import org.kotlintor.hs.OnionClient
import org.kotlintor.path.CircuitPath
import org.kotlintor.path.PathSelector
import java.nio.file.Files

class TorClient(
    private val config: TorConfig,
    private val scope: CoroutineScope,
    private val emitEvent: (TorEvent) -> Unit = {},
    firstHopDialer: (suspend (host: String, port: Int) -> java.net.Socket)? = null,
) {
    private val bootstrap = BootstrapTracker()
    private val dir = DirectoryClient(
        config.dataDirectory.resolve("dir"),
        authorities = buildAuthorities(config),
    )
    private val paths = PathSelector(config, config.dataDirectory.resolve("state/guards"))
    private val circuits = CircuitManager(
        scope,
        { line -> emitEvent(TorEvent.Circ(line)) },
        firstHopDialer,
        circuitBuildTimeoutMs = (config.circuitBuildTimeoutSec * 1000L).coerceAtLeast(5_000L),
        learnCircuitBuildTimeout = config.learnCircuitBuildTimeout,
        pathBiasOptions = config.pathBias.copy(
            dropGuards = config.pathBias.dropGuards || config.pathBiasDropGuards,
        ),
    ).also {
        it.pathBias.dropGuards = config.pathBias.dropGuards || config.pathBiasDropGuards
        it.pathBias.onGuardDropped = { fp -> paths.entryGuardFsm.disableForPathBias(fp) }
        if (config.circuitPriorityHalflifeMsec > 0) {
            it.applyConsensusParams(
                mapOf("CircuitPriorityHalflifeMsec" to config.circuitPriorityHalflifeMsec),
            )
        }
        it.schedulerPreference = config.schedulers
        it.circuitPaddingEnabled = config.circuitPadding && !config.reducedPadding
        it.reducedChannelPadding = config.reducedPadding
        it.connectionPaddingEnabled = when (config.padding) {
            org.kotlintor.config.AutoBool.NO -> false
            org.kotlintor.config.AutoBool.YES -> true
            org.kotlintor.config.AutoBool.AUTO -> when (config.connectionPadding) {
                org.kotlintor.config.AutoBool.NO -> false
                org.kotlintor.config.AutoBool.YES -> true
                org.kotlintor.config.AutoBool.AUTO -> !config.reducedPadding
            }
        }
        it.outboundBindOr = config.outboundBindForOr()
        it.constrainedSockSize = if (config.process.constrainedSockets) {
            config.process.constrainedSockSize
        } else {
            null
        }
    }
    private val automap: org.kotlintor.net.AutomapAddressMap? =
        if (config.automapHostsOnResolve) {
            org.kotlintor.net.AutomapAddressMap(
                virtualNetworkCidr = config.virtualAddrNetworkIpv4,
                suffixes = config.automapHostsSuffixes,
            )
        } else {
            null
        }
    private val geoIpDb: org.kotlintor.dir.GeoIp.Database? =
        config.geoIpFile?.let { path ->
            runCatching {
                org.kotlintor.dir.GeoIp.parseTorFormat(java.nio.file.Files.readString(path))
            }.getOrNull()
        }.also { db ->
            org.kotlintor.stats.GeoIpStats.setGeoDb(db)
        }
    init {
        val s = config.statsOptions
        org.kotlintor.stats.ConnStats.enabled = s.connDirectionStatistics || s.extraInfoStatistics
        org.kotlintor.stats.GeoIpStats.entryEnabled = s.entryStatistics
        org.kotlintor.stats.GeoIpStats.dirReqEnabled = s.dirReqStatistics
        org.kotlintor.stats.HsStats.enabled = s.hiddenServiceStatistics
    }
    private val mutex = Mutex()
    private var consensus: Consensus? = null
    private val hopKeys = linkedMapOf<String, HopKeys>()
    /** Indexed consensus relays (C Tor routerlist lite). */
    val routerList: org.kotlintor.dir.RouterList = org.kotlintor.dir.RouterList()
    /** Default (no isolation) exit circuit. */
    private var readyCircuit: Circuit? = null
    /** IsolateSOCKSAuth: one exit circuit per SOCKS username. */
    private val isolatedCircuits = linkedMapOf<String, Circuit>()
    private val onionClient = OnionClient(
        dir = dir,
        paths = paths,
        buildCircuit = { path, keys -> circuits.buildCircuit(path, keys) },
        ensureHopKeys = { fp ->
            ensureHopKeys(fp)
            hopKeys[fp]!!
        },
        identityCacheDir = config.dataDirectory.resolve("dir"),
    )

    val bootstrapTracker: BootstrapTracker get() = bootstrap
    val isBootstrapped: Boolean get() = bootstrap.phase.value.progress >= BootstrapPhase.LOADING_DESCRIPTORS.progress
    val hasCircuit: Boolean get() = readyCircuit != null

    fun circuitStatusLines(): List<String> = circuits.circuitStatusLines()

    suspend fun bootstrap(buildCircuit: Boolean = true) {
        Files.createDirectories(config.dataDirectory)
        bootstrap.advance(BootstrapPhase.CONN_DIR)
        bootstrap.advance(BootstrapPhase.HANDSHAKE_DIR)
        bootstrap.advance(BootstrapPhase.REQUESTING_STATUS)
        val c = if (config.useMicrodescriptors) {
            // Prefer microdesc-flavored consensus when UseMicrodescriptors=1; fall back to ns.
            runCatching { dir.fetchMicrodescConsensus() }.getOrElse { dir.fetchConsensus() }
        } else {
            dir.fetchConsensus()
        }
        consensus = c
        routerList.clear()
        routerList.addAll(c.relays)
        circuits.applyConsensusParams(c.params)
        bootstrap.advance(BootstrapPhase.LOADING_STATUS)
        bootstrap.advance(BootstrapPhase.LOADING_KEYS)
        bootstrap.advance(BootstrapPhase.REQUESTING_DESCRIPTORS)

        val path = paths.select(c.relays)
        ensureHopKeys(path.guard.fingerprintHex)
        ensureHopKeys(path.middle.fingerprintHex)
        ensureHopKeys(path.exit.fingerprintHex)
        bootstrap.advance(BootstrapPhase.LOADING_DESCRIPTORS)

        if (!buildCircuit) return

        var lastError: Exception? = null
        val excluded = mutableSetOf<String>()
        repeat(8) { attempt ->
            try {
                val p = paths.select(c.relays, extraExclude = excluded, rotateGuard = attempt > 0)
                ensureHopKeys(p.guard.fingerprintHex)
                ensureHopKeys(p.middle.fingerprintHex)
                ensureHopKeys(p.exit.fingerprintHex)
                bootstrap.advance(BootstrapPhase.CONN_OR)
                bootstrap.advance(BootstrapPhase.HANDSHAKE_OR)
                bootstrap.advance(BootstrapPhase.CIRCUIT_CREATE)
                readyCircuit = circuits.buildCircuit(p, hopKeys)
                paths.confirmGuard(p.guard.fingerprintHex)
                bootstrap.advance(BootstrapPhase.DONE)
                return
            } catch (e: Exception) {
                lastError = e
                System.err.println(
                    "circuit attempt ${attempt + 1} failed: ${e.javaClass.simpleName}: ${e.message}",
                )
                // On resource exhaustion / protocol errors, force a new guard next attempt.
                paths.rotateGuard()
            }
        }
        throw IllegalStateException("circuit bootstrap failed after retries", lastError)
    }

    /**
     * Open a stream to [host]:[port].
     * [isolationKey] is typically the SOCKS5 username when IsolateSOCKSAuth is set;
     * prefer [connect] with client/dest metadata via [buildIsolationKey].
     */
    suspend fun connect(
        host: String,
        port: Int,
        isolationKey: String? = null,
        clientAddr: String? = null,
        optimisticData: Boolean = config.optimisticData,
    ): TorStream {
        if (dormant) error("TorClient dormant: refusing new streams")
        val mapped = if (config.mapAddress.isEmpty()) {
            host
        } else {
            org.kotlintor.net.MapAddress.apply(
                host,
                config.mapAddress.map { org.kotlintor.net.MapAddress.Rule(it.first, it.second) },
            )
        }
        // Automap: reverse virtual IP → original hostname (.onion).
        val dest = automap?.reverse(mapped) ?: mapped
        if (config.safeSocks &&
            !HsClient.isOnionHost(dest) &&
            !org.kotlintor.net.SafeSocksPolicy.allows(
                dest,
                safeSocks = true,
                allowIpLiterals = config.safeSocksAllowIpLiterals,
            )
        ) {
            if (config.warnUnsafeSocks || config.testSocks) {
                System.err.println("SafeSocks: rejecting IP-literal destination $dest")
            }
            error("SafeSocks: refusing IP literal $dest (use a hostname)")
        }
        if (config.clientRejectInternalAddresses &&
            !HsClient.isOnionHost(dest) &&
            org.kotlintor.net.PrivateAddresses.isPrivate(dest)
        ) {
            error("ClientRejectInternalAddresses: refusing private destination $dest")
        }
        if (HsClient.isOnionHost(dest)) {
            val c = mutex.withLock { consensus } ?: error("no consensus; call bootstrap() first")
            return onionClient.connect(dest, port, c)
        }
        return mutex.withLock {
            val key = buildIsolationKey(
                socksUser = isolationKey,
                host = dest,
                port = port,
                clientAddr = clientAddr,
            )
            val circ = circuitForIsolation(key, dest, exitPort = port)
            circ.openStream(dest, port, optimisticData = optimisticData)
        }
    }

    /** Resolve [hostname] via RELAY RESOLVE on an exit circuit. */
    suspend fun resolve(hostname: String): List<String> = mutex.withLock {
        if (automap != null && automap.shouldAutomap(hostname)) {
            return@withLock listOf(automap.getOrAssign(hostname))
        }
        if (config.clientDnsRejectInternalAddresses &&
            org.kotlintor.net.PrivateAddresses.isPrivate(hostname)
        ) {
            return@withLock emptyList()
        }
        val circ = circuitForIsolation(null, hostname)
        circ.resolve(hostname)
    }

    private fun dirtyTimeoutMsFor(isolationKey: String?): Long {
        if (isolationKey != null &&
            IsolationFlag.KeepAliveIsolateSOCKSAuth in config.isolationFlags &&
            IsolationFlag.IsolateSOCKSAuth in config.isolationFlags
        ) {
            return Long.MAX_VALUE / 4 // prop368 IsoCDT ≈ infinity
        }
        return config.circuitDirtyTimeoutSec * 1000L
    }

    fun buildIsolationKey(
        socksUser: String?,
        host: String,
        port: Int,
        clientAddr: String?,
        protocol: String = "socks",
    ): String? {
        val parts = mutableListOf<String>()
        val flags = config.isolationFlags
        if (IsolationFlag.IsolateSOCKSAuth in flags && !socksUser.isNullOrEmpty()) {
            parts += "auth=$socksUser"
        }
        if (IsolationFlag.IsolateDestAddr in flags) parts += "dst=$host"
        if (IsolationFlag.IsolateDestPort in flags) parts += "dport=$port"
        if (IsolationFlag.IsolateClientAddr in flags && !clientAddr.isNullOrEmpty()) {
            parts += "caddr=$clientAddr"
        }
        if (IsolationFlag.IsolateClientProtocol in flags) parts += "proto=$protocol"
        return parts.takeIf { it.isNotEmpty() }?.joinToString("|")
    }

    private suspend fun circuitForIsolation(
        isolationKey: String?,
        host: String,
        exitPort: Int? = null,
    ): Circuit {
        if (!isolationKey.isNullOrEmpty()) {
            isolatedCircuits[isolationKey]?.let { existing ->
                if (!existing.isTooDirtyForAttach(dirtyTimeoutMsFor(isolationKey))) {
                    return existing
                }
                existing.close()
                isolatedCircuits.remove(isolationKey)
            }
            val c = consensus ?: error("no consensus; call bootstrap() first")
            val path = paths.select(c.relays, host, exitPort = exitPort)
            ensureHopKeys(path.guard.fingerprintHex)
            ensureHopKeys(path.middle.fingerprintHex)
            ensureHopKeys(path.exit.fingerprintHex)
            evictIsolatedIfNeeded()
            val circ = circuits.buildCircuit(path, hopKeys)
            paths.confirmGuard(path.guard.fingerprintHex)
            isolatedCircuits[isolationKey] = circ
            bootstrap.advance(BootstrapPhase.DONE)
            return circ
        }
        val existing = readyCircuit
        if (existing != null && !existing.isTooDirtyForAttach(dirtyTimeoutMsFor(null))) {
            return existing
        }
        existing?.close()
        readyCircuit = null
        val c = consensus ?: error("no consensus; call bootstrap() first")
        val path = paths.select(c.relays, host, exitPort = exitPort)
        ensureHopKeys(path.guard.fingerprintHex)
        ensureHopKeys(path.middle.fingerprintHex)
        ensureHopKeys(path.exit.fingerprintHex)
        val circ = circuits.buildCircuit(path, hopKeys)
        paths.confirmGuard(path.guard.fingerprintHex)
        readyCircuit = circ
        bootstrap.advance(BootstrapPhase.DONE)
        return circ
    }

    /** Download encrypted onion service v3 descriptor via BEGIN_DIR to responsible HSDirs. */
    suspend fun fetchOnionDescriptor(onionAddress: String): String {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        return onionClient.fetchDescriptor(onionAddress, c)
    }

    /** Fetch and decrypt a v3 onion descriptor (intro points plaintext). */
    suspend fun fetchAndDecryptOnionDescriptor(onionAddress: String): OnionClient.FetchedDescriptor {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        return onionClient.fetchAndDecrypt(onionAddress, c)
    }

    /** Debug: fetch HS descriptor from a named consensus relay via BEGIN_DIR. */
    suspend fun fetchOnionDescriptorVia(
        onionAddress: String,
        relayNicknameOrFp: String,
    ): String {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        val key = relayNicknameOrFp.uppercase()
        val relay = c.relays.find {
            it.nickname.equals(relayNicknameOrFp, true) || it.fingerprintHex == key
        } ?: error("relay not in consensus: $relayNicknameOrFp")
        return onionClient.fetchDescriptorFromRelay(onionAddress, c, relay)
    }

    /** Debug: BEGIN_DIR fetch against an explicit relay (may be absent from local consensus). */
    suspend fun fetchOnionDescriptorViaRelay(
        onionAddress: String,
        nickname: String,
        ip: String,
        orPort: Int,
        fingerprintHex: String,
    ): String {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        val fp = fingerprintHex.uppercase()
        val identity = org.kotlintor.util.hexToBytes(fp)
        val relay = RouterStatus(
            nickname = nickname,
            identity = identity,
            digest = ByteArray(20),
            publication = c.validAfter,
            ip = ip,
            orPort = orPort,
            dirPort = 0,
            flags = setOf("Running", "Fast", "HSDir", "V2Dir"),
            version = null,
            proto = emptyMap(),
            bandwidth = 1,
        )
        // Ensure path selection can still find guards/middles from consensus.
        return onionClient.fetchDescriptorFromRelay(onionAddress, c, relay)
    }

    private suspend fun ensureHopKeys(fp: String) {
        if (fp in hopKeys) return
        val docs = dir.fetchServerDescriptors(listOf(fp))
        val doc = docs.entries.firstOrNull { it.key.equals(fp, true) }?.value
            ?: docs.values.firstOrNull()
            ?: error("no descriptor for $fp")
        val parsed = DescriptorParser.parse(doc, fp) ?: error("bad descriptor for $fp")
        hopKeys[fp] = HopKeys(parsed.ntorOnionKey, parsed.ed25519Identity)
        while (hopKeys.size > MAX_HOP_KEYS) {
            val oldest = hopKeys.keys.firstOrNull() ?: break
            hopKeys.remove(oldest)
        }
        val family = DescriptorParser.parseFamily(doc)
        if (family.isNotEmpty()) {
            paths.noteFamily(fp, family)
        }
    }

    private fun evictIsolatedIfNeeded() {
        while (isolatedCircuits.size >= MAX_ISOLATED_CIRCUITS) {
            val oldest = isolatedCircuits.entries.firstOrNull() ?: break
            oldest.value.close()
            isolatedCircuits.remove(oldest.key)
        }
    }

    fun newnym() {
        readyCircuit?.close()
        readyCircuit = null
        isolatedCircuits.values.forEach { it.close() }
        isolatedCircuits.clear()
    }

    /** Drop ready + isolated circuits (OnionTunnel RefreshCircuits). */
    fun refreshCircuits() = newnym()

    /**
     * Soft dormant flag for OnionTunnel scaffolding.
     * When dormant, [connect] refuses new streams until cleared.
     */
    @Volatile
    var dormant: Boolean = false
        private set

    fun setDormant(value: Boolean) {
        dormant = value
    }

    fun consensusOrNull(): Consensus? = consensus

    /** HS host: build an arbitrary circuit path. */
    suspend fun buildCircuitForHs(path: CircuitPath, keys: Map<String, HopKeys>): Circuit =
        circuits.buildCircuit(path, keys)

    suspend fun hopKeysFor(fp: String): HopKeys {
        ensureHopKeys(fp)
        return hopKeys[fp]!!
    }

    fun selectPathEndingAt(relays: List<RouterStatus>, last: RouterStatus): CircuitPath =
        paths.selectEndingAt(relays, last)

    fun sampledGuardStatusLines(): List<String> =
        paths.sampledEntries().map { e ->
            val status = when {
                e.confirmed -> "confirmed"
                else -> "unconfirmed"
            }
            "${e.fingerprintHex} $status first=${e.firstListedMs}"
        }

    /** Upload a signed HS v3 descriptor to responsible HSDirs. */
    suspend fun publishOnionDescriptor(document: String, blindedPublic: ByteArray): Int {
        val c = consensus ?: error("no consensus; call bootstrap() first")
        return onionClient.publishDescriptor(document, blindedPublic, c)
    }

    companion object {
        const val MAX_HOP_KEYS = 512
        const val MAX_ISOLATED_CIRCUITS = 128

        fun buildAuthorities(config: TorConfig): List<org.kotlintor.dir.DirectoryAuthority> {
            if (config.dirAuthorities.isNotEmpty()) return config.dirAuthorities
            val fallbacks = if (config.useDefaultFallbackDirs) {
                config.fallbackDirs
            } else {
                config.fallbackDirs
            }
            return if (fallbacks.isNotEmpty()) {
                fallbacks
            } else {
                org.kotlintor.dir.DefaultAuthorities.ALL
            }
        }
    }
}
