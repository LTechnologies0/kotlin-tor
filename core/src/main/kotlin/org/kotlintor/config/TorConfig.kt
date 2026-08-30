package org.kotlintor.config

import java.nio.file.Path

/**
 * Typed subset of torrc options for kotlin-tor (C Tor surface parity, growing).
 */
data class TorConfig(
    val dataDirectory: Path,
    val socksPorts: List<ListenSpec> = listOf(ListenSpec("127.0.0.1", 9050)),
    val controlPorts: List<ListenSpec> = listOf(ListenSpec("127.0.0.1", 9051)),
    val controlSockets: List<Path> = emptyList(),
    val cookieAuthentication: Boolean = true,
    val hashedControlPassword: String? = null,
    val clientOnly: Boolean = true,
    val useBridges: Boolean = false,
    val bridges: List<String> = emptyList(),
    val excludeNodes: List<String> = emptyList(),
    val excludeExitNodes: List<String> = emptyList(),
    val orPort: ListenSpec? = null,
    val extOrPort: ListenSpec? = null,
    val dirPort: ListenSpec? = null,
    val metricsPort: ListenSpec? = null,
    val exitRelay: Boolean = false,
    val reducedExitPolicy: Boolean = false,
    /** Raw ExitPolicy lines (`accept …` / `reject …`), evaluated in order. */
    val exitPolicyLines: List<String> = emptyList(),
    /** ExitPolicyRejectPrivate — reject RFC1918/loopback exits (default true). */
    val exitPolicyRejectPrivate: Boolean = true,
    /** ExitPolicyRejectLocalInterfaces — reject this host's NIC addresses. */
    val exitPolicyRejectLocalInterfaces: Boolean = true,
    /** IPv6Exit — advertise/allow IPv6 exit (descriptor flag). */
    val ipv6Exit: Boolean = false,
    /** ExitNodes / MiddleNodes allowlists (empty = any). */
    val exitNodes: List<String> = emptyList(),
    val middleNodes: List<String> = emptyList(),
    /** BridgeAuthoritativeDir — act as bridge authority. */
    val bridgeAuthoritativeDir: Boolean = false,
    /** BridgeDistribution hint string. */
    val bridgeDistribution: String = "any",
    /** CircuitPadding / ConnectionPadding / ReducedPadding. */
    val circuitPadding: Boolean = true,
    val connectionPadding: AutoBool = AutoBool.AUTO,
    val reducedPadding: Boolean = false,
    /** AssumeReachableIPv6. */
    val assumeReachableIpv6: Boolean = false,
    /** Statistics feature flags. */
    val statsOptions: StatsOptions = StatsOptions.DEFAULT,
    /** GuardLifetime days (default ~240). */
    val guardLifetimeDays: Long = 240,
    /** NumDirectoryGuards. */
    val numDirectoryGuards: Int = 3,
    /** GuardsKeepDesc. */
    val guardsKeepDesc: Boolean = true,
    /** Custom DirAuthority entries (empty → DefaultAuthorities). */
    val dirAuthorities: List<org.kotlintor.dir.DirectoryAuthority> = emptyList(),
    /** FallbackDir entries. */
    val fallbackDirs: List<org.kotlintor.dir.DirectoryAuthority> = emptyList(),
    /** UseDefaultFallbackDirs. */
    val useDefaultFallbackDirs: Boolean = true,
    /** FetchHidServDescriptors / FetchServerDescriptors. */
    val fetchHidServDescriptors: Boolean = true,
    val fetchServerDescriptors: Boolean = true,
    /** ClientDNSRejectInternalAddresses. */
    val clientDnsRejectInternalAddresses: Boolean = true,
    /**
     * DNSSECMode — Off keeps RELAY RESOLVE; Validate uses fail-closed local DNSSEC
     * over Tor TCP to [dnssecRecursive] (not DNSCrypt).
     */
    val dnssecMode: org.kotlintor.net.dns.DnssecMode = org.kotlintor.net.dns.DnssecMode.OFF,
    /** Recursive DNS endpoint `host:port` for DNSSEC stub (TCP/53 via Tor). */
    val dnssecRecursive: String = "1.1.1.1:53",
    /** Optional DS trust-anchor file; null → bundled IANA root anchors. */
    val dnssecTrustAnchorFile: Path? = null,
    /** Advertised IPv4 Address= for relay descriptor. */
    val address: String? = null,
    /** OutboundBindAddress (generic) + OR/Exit/PT overrides. */
    val outboundBindAddress: String? = null,
    val outboundBindAddressOr: String? = null,
    val outboundBindAddressExit: String? = null,
    val outboundBindAddressPt: String? = null,
    /** FascistFirewall + FirewallPorts. */
    val fascistFirewall: Boolean = false,
    val firewallPorts: Set<Int> = emptySet(),
    /** ReachableORAddresses / ReachableDirAddresses / ReachableAddresses lines. */
    val reachableOrAddresses: List<String> = emptyList(),
    val reachableDirAddresses: List<String> = emptyList(),
    val reachableAddresses: List<String> = emptyList(),
    /** SafeSocks / TestSocks / WarnUnsafeSocks. */
    val safeSocks: Boolean = false,
    val testSocks: Boolean = false,
    val warnUnsafeSocks: Boolean = true,
    /**
     * When true with [safeSocks], allow IP-literal destinations (VPN / OnionTunnel
     * fake-IP cookie path). Not a torrc key — product surface for Phase OM.
     */
    val safeSocksAllowIpLiterals: Boolean = false,
    /** SocksTimeout seconds. */
    val socksTimeoutSec: Long = 120,
    /** MaxAdvertisedBandwidth (bytes/sec). */
    val maxAdvertisedBandwidthBytes: Long = 0,
    /** RelayBandwidthRate / Burst (0 = use BandwidthRate). */
    val relayBandwidthRateBytes: Long = 0,
    val relayBandwidthBurstBytes: Long = 0,
    /** PerConnBWRate / Burst. */
    val perConnBwRateBytes: Long = 0,
    val perConnBwBurstBytes: Long = 0,
    /** CookieAuthFile path override. */
    val cookieAuthFile: java.nio.file.Path? = null,
    /** KeyDirectory / CacheDirectory overrides. */
    val keyDirectory: java.nio.file.Path? = null,
    val cacheDirectory: java.nio.file.Path? = null,
    /** PublishHidServDescriptors. */
    val publishHidServDescriptors: Boolean = true,
    /** Padding (AUTOBOOL). */
    val padding: AutoBool = AutoBool.AUTO,
    /** CircuitIdleTimeout / CircuitStreamTimeout seconds. */
    val circuitIdleTimeoutSec: Long = 3600,
    val circuitStreamTimeoutSec: Long = 0,
    val hiddenServices: List<HiddenServiceConfig> = emptyList(),
    val safeLogging: Boolean = true,
    val logLevel: LogLevel = LogLevel.NOTICE,
    /** C Tor `quiet_level` — startup default log when no Log lines configured. */
    val quietLevel: QuietLevel = QuietLevel.NONE,
    val isolationFlags: Set<IsolationFlag> = emptySet(),
    val clientUseIpv4: Boolean = true,
    val clientUseIpv6: Boolean = true,
    val clientRejectInternalAddresses: Boolean = true,
    /** Explicit MyFamily / NodeFamily nicknames or fingerprints (torrc). */
    val nodeFamily: List<String> = emptyList(),
    /** CircuitDirtyTimeout seconds (prop368 dirty attach cutoff). Default 10 minutes. */
    val circuitDirtyTimeoutSec: Long = 600,
    /** Unused circuit timeout seconds after last stream closes. Default 10 minutes. */
    val circuitUnusedTimeoutSec: Long = 600,
    /** When true, avoid same-/16 for distinct hops (path-spec). */
    val enforceDistinctSubnets: Boolean = true,
    /**
     * Client-local: avoid same GeoIP country across hops in one circuit.
     * Does not alter consensus; requires [geoIpFile] for effect.
     */
    val enforceDistinctCountries: Boolean = true,
    /**
     * Client-local: avoid same continent (derived from country) across hops.
     * Does not alter consensus; requires [geoIpFile] for effect.
     */
    val enforceDistinctContinents: Boolean = true,
    /** Client-local: avoid recently used middle/exit fingerprints on new circuits. */
    val circuitAvoidRecentHops: Boolean = true,
    /** Max fingerprints retained for [circuitAvoidRecentHops] (middle/exit only). */
    val circuitRecentHopHistorySize: Int = 64,
    val dnsPort: ListenSpec? = null,
    /**
     * Local UDP-over-TCP gateway listen (kotlin-tor extension). Pair with SOCKS5
     * UDP ASSOCIATE so datagrams ride Tor TCP to this process (`UdpTorGatewayServer`).
     */
    val udpTorGatewayPort: ListenSpec? = null,
    val publishServerDescriptor: Boolean = true,
    val clientTransportPlugin: String? = null,
    /** Server-side PT plugin line (`ServerTransportPlugin obfs4 exec …`). */
    val serverTransportPlugin: String? = null,
    /** ServerTransportListenAddr lines (`obfs4 0.0.0.0:12345`). */
    val serverTransportListenAddr: List<String> = emptyList(),
    val optimisticData: Boolean = true,
    val transPort: ListenSpec? = null,
    val vanguardsLiteEnabled: Boolean = true,
    val owningControllerProcess: Long? = null,
    val onionKeyRotationDays: Int = 28,
    val heartbeatPeriodSec: Long = 21600,
    /** torrc Sandbox — process hardening + seccomp-bpf via FFM (see LinuxSandbox). */
    val sandbox: Boolean = false,
    /** When true, no outbound OR/dir; control still works (torrc DisableNetwork). */
    val disableNetwork: Boolean = false,
    /** Relay Nickname (torrc). */
    val nickname: String = "KotlinTor",
    /** ContactInfo for descriptors. */
    val contactInfo: String = "kotlin-tor@localhost",
    /** BandwidthRate in bytes/sec (parsed from torrc with optional KB/MB). Default 1 MB/s. */
    val bandwidthRateBytes: Long = 1_000_000,
    /** BandwidthBurst in bytes/sec. */
    val bandwidthBurstBytes: Long = 1_000_000,
    /** CircuitBuildTimeout seconds (path-spec). Default 60. */
    val circuitBuildTimeoutSec: Long = 60,
    /** Max simultaneous client circuits pending (torrc MaxClientCircuitsPending). */
    val maxClientCircuitsPending: Int = 32,
    /** Soft connection limit hint (torrc ConnLimit); applied via sandbox prlimit when Sandbox=1. */
    val connLimit: Int = 1000,
    /** KeepalivePeriod seconds between OR padding keepalives. */
    val keepalivePeriodSec: Long = 300,
    /** FetchDirInfoEarly — prefer early consensus fetch. */
    val fetchDirInfoEarly: Boolean = false,
    /** AvoidDiskWrites — prefer in-memory caches where possible. */
    val avoidDiskWrites: Boolean = false,
    /** DisableDebuggerAttachment — prefer seccomp deny-ptrace when Sandbox=1. */
    val disableDebuggerAttachment: Boolean = true,
    /** UseEntryGuards — sticky sampled guards (guard-spec). */
    val useEntryGuards: Boolean = true,
    /** NumEntryGuards / sampled primary set size. */
    val numEntryGuards: Int = 3,
    /** EntryNodes allowlist (nicknames/fingerprints); empty = any guard. */
    val entryNodes: List<String> = emptyList(),
    /** StrictNodes — treat EntryNodes/ExcludeNodes as hard requirements. */
    val strictNodes: Boolean = false,
    /** HTTPTunnelPort (HTTP CONNECT listener). */
    val httpTunnelPort: ListenSpec? = null,
    /**
     * Ports that prefer Stable exits (torrc LongLivedPorts).
     * Default matches C Tor: 21,22,706,1863,5050,5190,5222,5223,6523,6667,6697,8300
     */
    val longLivedPorts: Set<Int> = DEFAULT_LONG_LIVED_PORTS,
    /** MapAddress rewrite rules (from → to). */
    val mapAddress: List<Pair<String, String>> = emptyList(),
    /** AccountingMax bytes (0 = disabled). Soft hibernate threshold; hard = 2× soft when unset. */
    val accountingMaxBytes: Long = 0,
    /** AccountingStart interval seconds (default 30 days). */
    val accountingIntervalSec: Long = 30L * 24 * 3600,
    /** PathBias* rates/thresholds (circpathbias.c). */
    val pathBias: PathBiasOptions = PathBiasOptions.DEFAULT,
    /** PathBiasDropGuards — disable guards at EXTREME path bias. */
    val pathBiasDropGuards: Boolean = false,
    /** GeoIPFile path for country lookups. */
    val geoIpFile: Path? = null,
    /** AutomapHostsOnResolve. */
    val automapHostsOnResolve: Boolean = false,
    /** AutomapHostsSuffixes. */
    val automapHostsSuffixes: List<String> = listOf(".onion", ".exit"),
    /** VirtualAddrNetworkIPv4. */
    val virtualAddrNetworkIpv4: String = "127.192.0.0/10",
    /** MaxOnionQueueDelay milliseconds (0 = no expiry). */
    val maxOnionQueueDelayMs: Long = 0,
    /**
     * CircuitPriorityHalflife / CircuitPriorityHalflifeMsec for EWMA cmux.
     * When > 0, applied as CircuitPriorityHalflifeMsec before consensus overrides.
     */
    val circuitPriorityHalflifeMsec: Long = 0,
    /** Typed DoS subsystem options (`dos_options_t`). */
    val dosOptions: org.kotlintor.relay.DosOptions = org.kotlintor.relay.DosOptions(),
    /** NewCircuitPeriod seconds — hint for circuit rotation (path-spec). */
    val newCircuitPeriodSec: Long = 30,
    /** LearnCircuitBuildTimeout — blend CBT quantile with CircuitBuildTimeout. */
    val learnCircuitBuildTimeout: Boolean = true,
    /** Schedulers= preference list: vanilla, kist, or kist_lite. */
    val schedulers: List<org.kotlintor.link.SchedulerType> =
        listOf(org.kotlintor.link.SchedulerType.KIST, org.kotlintor.link.SchedulerType.VANILLA),
    /** AuthoritativeDirectory / V3AuthoritativeDirectory — run dirvote publish loop. */
    val authoritativeDirectory: Boolean = false,
    val v3AuthoritativeDirectory: Boolean = false,
    /** TestingTorNetwork — shorter vote intervals. */
    val testingTorNetwork: Boolean = false,
    /** UseMicrodescriptors — prefer microdesc consensus (default true). */
    val useMicrodescriptors: Boolean = true,
    /** FetchUselessDescriptors. */
    val fetchUselessDescriptors: Boolean = false,
    /** DownloadExtraInfo. */
    val downloadExtraInfo: Boolean = false,
    /** AssumeReachable — skip ORPort reachability self-test gate. */
    val assumeReachable: Boolean = false,
    /** BridgeRelay — act as bridge; do not publish to public DirAuths. */
    val bridgeRelay: Boolean = false,
    /** ExtendAllowPrivateAddresses — allow EXTEND2 to RFC1918 / loopback. */
    val extendAllowPrivateAddresses: Boolean = false,
    /** DirAllowPrivateAddresses — allow DirPort peers from private addrs. */
    val dirAllowPrivateAddresses: Boolean = false,
    /**
     * RefuseUnknownExits (AUTOBOOL): refuse exit BEGIN on one-hop / unknown-relay
     * circuits. Default [AutoBool.AUTO] follows consensus `refuseunknownexits=1`.
     */
    val refuseUnknownExits: AutoBool = AutoBool.AUTO,
    /** FetchDirInfoExtraEarly — requires FetchDirInfoEarly; prefer earliest fetch. */
    val fetchDirInfoExtraEarly: Boolean = false,
    /** Process / misc options (PidFile, NumCPUs, ConstrainedSockets, …). */
    val process: ProcessOptions = ProcessOptions(),
    /** ServerDNS* options for exit DNS. */
    val serverDns: ServerDnsOptions = ServerDnsOptions(),
    /** Dormant / Conflux / KIST / testing / outbound-proxy options (C Tor or_options). */
    val runtime: ClientRuntimeOptions = ClientRuntimeOptions(),
    /**
     * Keys listed in [TorrcManpageKeys] that are not yet fully typed into dedicated fields.
     * Retained for GETCONF / SAVECONF parity with C Tor.
     */
    val acknowledgedKeys: Map<String, String> = emptyMap(),
    /** Truly unknown torrc keys (not in manpage catalog). */
    val unrecognizedKeys: Map<String, String> = emptyMap(),
) {
    val isRelay: Boolean get() = orPort != null && !clientOnly

    fun isLongLivedPort(port: Int): Boolean = port in longLivedPorts

    /** C Tor `should_refuse_unknown_exits` (AUTO → treat as enabled). */
    fun shouldRefuseUnknownExits(consensusParam: Boolean = true): Boolean =
        when (refuseUnknownExits) {
            AutoBool.YES -> true
            AutoBool.NO -> false
            AutoBool.AUTO -> consensusParam
        }

    fun outboundBindForOr(): String? = outboundBindAddressOr ?: outboundBindAddress
    fun outboundBindForExit(): String? = outboundBindAddressExit ?: outboundBindAddress
    fun outboundBindForPt(): String? = outboundBindAddressPt ?: outboundBindAddress

    /** Combined OR reachability policy (FascistFirewall ∪ ReachableOR ∪ Reachable). */
    fun orReachablePolicy(): org.kotlintor.net.AddrPolicy {
        if (fascistFirewall) {
            return org.kotlintor.net.AddrPolicy.fascist(firewallPorts)
        }
        val lines = reachableOrAddresses.ifEmpty { reachableAddresses }
        return org.kotlintor.net.AddrPolicy.parseLines(lines)
    }

    /** SocksPolicy for client source addresses (empty → allow all). */
    fun socksClientPolicy(): org.kotlintor.net.AddrPolicy =
        org.kotlintor.net.AddrPolicy.parseLines(process.socksPolicyLines)

    /** Apply ConstrainedSockets buffer sizes when enabled. */
    fun applyConstrainedBuffers(sock: java.net.Socket) {
        if (!process.constrainedSockets) return
        val n = process.constrainedSockSize.coerceIn(512, 65536)
        runCatching {
            sock.receiveBufferSize = n
            sock.sendBufferSize = n
        }
    }

    companion object {
        val DEFAULT_LONG_LIVED_PORTS: Set<Int> = setOf(
            21, 22, 706, 1863, 5050, 5190, 5222, 5223, 6523, 6667, 6697, 8300,
        )
    }
}

/** C Tor AUTOBOOL: 0 / 1 / auto. */
enum class AutoBool {
    NO, YES, AUTO;

    fun toTorrc(): String = when (this) {
        NO -> "0"
        YES -> "1"
        AUTO -> "auto"
    }

    companion object {
        fun parse(raw: String): AutoBool = when (raw.trim().lowercase()) {
            "1", "true", "yes", "on" -> YES
            "0", "false", "no", "off" -> NO
            "auto" -> AUTO
            else -> AUTO
        }
    }
}

data class ListenSpec(val host: String, val port: Int) {
    override fun toString(): String = if (host.isEmpty()) port.toString() else "$host:$port"

    /** True for empty host, localhost, 127.0.0.1, ::1, or InetAddress loopback. */
    fun isLoopbackHost(): Boolean {
        val h = host.trim().lowercase()
        if (h.isEmpty() || h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]") {
            return true
        }
        return runCatching {
            java.net.InetAddress.getByName(host.removeSurrounding("[", "]")).isLoopbackAddress
        }.getOrDefault(false)
    }

    companion object {
        fun parse(raw: String): ListenSpec {
            val t = raw.trim()
            if (t == "0" || t.equals("auto", true)) return ListenSpec("127.0.0.1", 0)
            val idx = t.lastIndexOf(':')
            return if (idx > 0 && !t.startsWith("unix:")) {
                ListenSpec(t.substring(0, idx), t.substring(idx + 1).toInt())
            } else {
                ListenSpec("127.0.0.1", t.toInt())
            }
        }
    }
}

data class HiddenServiceConfig(
    val directory: Path,
    val ports: List<HiddenServicePort>,
    val version: Int = 3,
    val powEnabled: Boolean = false,
    val powEffort: Int = 20,
    /** Max INTRODUCE2 admissions per minute (0 = unlimited). */
    val maxIntroducesPerMin: Int = 200,
    /** HiddenServiceNumIntroductionPoints (default 3). */
    val numIntroductionPoints: Int = 3,
    /** HiddenServiceMaxStreams (0 = unlimited). */
    val maxStreams: Int = 0,
    /** HiddenServiceMaxStreamsCloseCircuit. */
    val maxStreamsCloseCircuit: Boolean = false,
    /** HiddenServiceEnableIntroDoSDefense. */
    val introDosDefense: Boolean = false,
    val introDosBurstPerSec: Int = 200,
    val introDosRatePerSec: Int = 25,
    /** HiddenServicePoWQueueBurst. */
    val powQueueBurst: Int = 250,
    /** HiddenServiceOnionBalanceInstance. */
    val onionBalanceInstance: Boolean = false,
    /** HiddenServiceSingleHopMode / NonAnonymousMode. */
    val singleHopMode: Boolean = false,
    val nonAnonymousMode: Boolean = false,
    /** HiddenServiceDirGroupReadable. */
    val dirGroupReadable: Boolean = false,
    /** HiddenServiceExportCircuitID (e.g. "haproxy"). */
    val exportCircuitId: String? = null,
)

data class HiddenServicePort(val virtualPort: Int, val target: String)

enum class LogLevel { DEBUG, INFO, NOTICE, WARN, ERR }

enum class IsolationFlag {
    IsolateClientAddr,
    IsolateSOCKSAuth,
    IsolateClientProtocol,
    IsolateDestPort,
    IsolateDestAddr,
    KeepAliveIsolateSOCKSAuth,
}

object TorrcParser {
    /** Parse `1 MB`, `100 KB`, or bare integer bytes. */
    fun parseBandwidth(raw: String): Long? {
        val t = raw.trim()
        val parts = t.split(Regex("\\s+"))
        val n = parts[0].toLongOrNull() ?: return null
        val unit = parts.getOrElse(1) { "" }.uppercase()
        return when {
            unit.startsWith("G") -> n * 1_000_000_000
            unit.startsWith("M") -> n * 1_000_000
            unit.startsWith("K") -> n * 1_000
            else -> n
        }
    }

    fun parse(text: String, dataDirDefault: Path): TorConfig {
        var dataDirectory = dataDirDefault
        val socks = mutableListOf<ListenSpec>()
        val control = mutableListOf<ListenSpec>()
        val controlSocks = mutableListOf<Path>()
        var cookieAuth = true
        var hashed: String? = null
        var clientOnly = true
        var useBridges = false
        val bridges = mutableListOf<String>()
        val exclude = mutableListOf<String>()
        val excludeExit = mutableListOf<String>()
        var orPort: ListenSpec? = null
        var extOr: ListenSpec? = null
        var dirPort: ListenSpec? = null
        var metricsPort: ListenSpec? = null
        var exitRelay = false
        var reducedExit = false
        val exitPolicies = mutableListOf<String>()
        var exitPolicyRejectPrivate = true
        var exitPolicyRejectLocalInterfaces = true
        var ipv6Exit = false
        val exitNodes = mutableListOf<String>()
        val middleNodes = mutableListOf<String>()
        var bridgeAuthoritativeDir = false
        var bridgeDistribution = "any"
        var circuitPadding = true
        var connectionPadding = AutoBool.AUTO
        var reducedPadding = false
        var assumeReachableIpv6 = false
        var clientUseIpv4 = true
        var clientUseIpv6 = true
        var clientRejectInternalAddresses = true
        val hs = mutableListOf<HiddenServiceConfig>()
        var currentHsDir: Path? = null
        val currentHsPorts = mutableListOf<HiddenServicePort>()
        var currentHsPow = false
        var currentHsPowEffort = 20
        var currentHsIntroRate = 200
        var currentHsNumIntros = 3
        var currentHsMaxStreams = 0
        var currentHsMaxStreamsClose = false
        var currentHsIntroDos = false
        var currentHsIntroDosBurst = 200
        var currentHsIntroDosRate = 25
        var currentHsPowBurst = 250
        var currentHsOnionBalance = false
        var currentHsSingleHop = false
        var currentHsNonAnon = false
        var currentHsDirGroupReadable = false
        var currentHsExportCircuitId: String? = null
        var currentHsVersion = 3
        var statsOpts = StatsOptions.DEFAULT
        var guardLifetimeDays = 240L
        var numDirectoryGuards = 3
        var guardsKeepDesc = true
        val dirAuthorities = mutableListOf<org.kotlintor.dir.DirectoryAuthority>()
        val fallbackDirs = mutableListOf<org.kotlintor.dir.DirectoryAuthority>()
        var useDefaultFallbackDirs = true
        var fetchHidServDescriptors = true
        var fetchServerDescriptors = true
        var clientDnsRejectInternalAddresses = true
        var dnssecMode = org.kotlintor.net.dns.DnssecMode.OFF
        var dnssecRecursive = "1.1.1.1:53"
        var dnssecTrustAnchorFile: Path? = null
        var address: String? = null
        var outboundBind: String? = null
        var outboundBindOr: String? = null
        var outboundBindExit: String? = null
        var outboundBindPt: String? = null
        var fascistFirewall = false
        val firewallPorts = mutableSetOf<Int>()
        val reachableOr = mutableListOf<String>()
        val reachableDir = mutableListOf<String>()
        val reachableAny = mutableListOf<String>()
        var safeSocks = false
        var testSocks = false
        var warnUnsafeSocks = true
        var socksTimeoutSec = 120L
        var maxAdvertisedBandwidthBytes = 0L
        var relayBandwidthRateBytes = 0L
        var relayBandwidthBurstBytes = 0L
        var perConnBwRateBytes = 0L
        var perConnBwBurstBytes = 0L
        var cookieAuthFile: Path? = null
        var keyDirectory: Path? = null
        var cacheDirectory: Path? = null
        var publishHidServDescriptors = true
        var padding = AutoBool.AUTO
        var circuitIdleTimeoutSec = 3600L
        var circuitStreamTimeoutSec = 0L
        var processOpts = ProcessOptions()
        var serverDnsOpts = ServerDnsOptions()
        val isolation = mutableSetOf<IsolationFlag>()
        var safeLogging = true
        var logLevel = LogLevel.NOTICE
        val nodeFamily = mutableListOf<String>()
        var circuitDirtyTimeoutSec = 600L
        var circuitUnusedTimeoutSec = 600L
        var enforceDistinctSubnets = true
        var enforceDistinctCountries = true
        var enforceDistinctContinents = true
        var circuitAvoidRecentHops = true
        var circuitRecentHopHistorySize = 64
        var dnsPort: ListenSpec? = null
        var udpTorGatewayPort: ListenSpec? = null
        var publishServerDescriptor = true
        var clientTransportPlugin: String? = null
        var serverTransportPlugin: String? = null
        val serverTransportListenAddr = mutableListOf<String>()
        var optimisticData = true
        var transPort: ListenSpec? = null
        var vanguardsLiteEnabled = true
        var owningControllerProcess: Long? = null
        var onionKeyRotationDays = 28
        var heartbeatPeriodSec = 21600L
        var sandbox = false
        var disableNetwork = false
        var nickname = "KotlinTor"
        var contactInfo = "kotlin-tor@localhost"
        var bandwidthRateBytes = 1_000_000L
        var bandwidthBurstBytes = 1_000_000L
        var circuitBuildTimeoutSec = 60L
        var maxClientCircuitsPending = 32
        var connLimit = 1000
        var keepalivePeriodSec = 300L
        var fetchDirInfoEarly = false
        var avoidDiskWrites = false
        var disableDebuggerAttachment = true
        var useEntryGuards = true
        var numEntryGuards = 3
        var strictNodes = false
        val entryNodes = mutableListOf<String>()
        var httpTunnelPort: ListenSpec? = null
        var longLivedPorts: Set<Int>? = null
        val mapAddress = mutableListOf<Pair<String, String>>()
        var accountingMaxBytes = 0L
        var accountingIntervalSec = 30L * 24 * 3600
        var pathBiasOpts = PathBiasOptions.DEFAULT
        var pathBiasDropGuards = false
        var geoIpFile: Path? = null
        var automapHostsOnResolve = false
        var automapHostsSuffixes = listOf(".onion", ".exit")
        var virtualAddrNetworkIpv4 = "127.192.0.0/10"
        var maxOnionQueueDelayMs = 0L
        var circuitPriorityHalflifeMsec = 0L
        var dosOpts = org.kotlintor.relay.DosOptions()
        var newCircuitPeriodSec = 30L
        var learnCircuitBuildTimeout = true
        var schedulers = listOf(
            org.kotlintor.link.SchedulerType.KIST,
            org.kotlintor.link.SchedulerType.VANILLA,
        )
        var authoritativeDirectory = false
        var v3AuthoritativeDirectory = false
        var testingTorNetwork = false
        var useMicrodescriptors = true
        var fetchUselessDescriptors = false
        var downloadExtraInfo = false
        var assumeReachable = false
        var bridgeRelay = false
        var extendAllowPrivateAddresses = false
        var dirAllowPrivateAddresses = false
        var refuseUnknownExits = AutoBool.AUTO
        var fetchDirInfoExtraEarly = false
        var runtimeOpts = ClientRuntimeOptions()
        val acknowledged = linkedMapOf<String, String>()
        val unrecognized = linkedMapOf<String, String>()

        fun flushHs() {
            val dir = currentHsDir ?: return
            hs += HiddenServiceConfig(
                directory = dir,
                ports = currentHsPorts.toList(),
                version = currentHsVersion,
                powEnabled = currentHsPow,
                powEffort = currentHsPowEffort,
                maxIntroducesPerMin = currentHsIntroRate,
                numIntroductionPoints = currentHsNumIntros,
                maxStreams = currentHsMaxStreams,
                maxStreamsCloseCircuit = currentHsMaxStreamsClose,
                introDosDefense = currentHsIntroDos,
                introDosBurstPerSec = currentHsIntroDosBurst,
                introDosRatePerSec = currentHsIntroDosRate,
                powQueueBurst = currentHsPowBurst,
                onionBalanceInstance = currentHsOnionBalance,
                singleHopMode = currentHsSingleHop,
                nonAnonymousMode = currentHsNonAnon,
                dirGroupReadable = currentHsDirGroupReadable,
                exportCircuitId = currentHsExportCircuitId,
            )
            currentHsDir = null
            currentHsPorts.clear()
            currentHsPow = false
            currentHsPowEffort = 20
            currentHsIntroRate = 200
            currentHsNumIntros = 3
            currentHsMaxStreams = 0
            currentHsMaxStreamsClose = false
            currentHsIntroDos = false
            currentHsIntroDosBurst = 200
            currentHsIntroDosRate = 25
            currentHsPowBurst = 250
            currentHsOnionBalance = false
            currentHsSingleHop = false
            currentHsNonAnon = false
            currentHsDirGroupReadable = false
            currentHsExportCircuitId = null
            currentHsVersion = 3
        }

        for (rawLine in text.lineSequence()) {
            val line = rawLine.substringBefore('#').trim()
            if (line.isEmpty()) continue
            val parts = line.split(Regex("\\s+"), limit = 2)
            val key = parts[0]
            val value = parts.getOrElse(1) { "" }.trim()
            when (key) {
                "DataDirectory" -> dataDirectory = Path.of(value)
                "SocksPort" -> {
                    val tokens = value.split(Regex("\\s+"))
                    socks += ListenSpec.parse(tokens.first())
                    tokens.drop(1).forEach { tok ->
                        runCatching { IsolationFlag.valueOf(tok) }.getOrNull()?.let { isolation += it }
                    }
                }
                "ControlPort" -> control += ListenSpec.parse(value)
                "ControlSocket" -> controlSocks.add(Path.of(value))
                "CookieAuthentication" -> cookieAuth = value == "1"
                "HashedControlPassword" -> hashed = value
                "ClientOnly" -> clientOnly = value == "1"
                "UseBridges" -> useBridges = value == "1"
                "Bridge" -> bridges += value
                "ExcludeNodes" -> exclude += value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                "ExcludeExitNodes" -> excludeExit += value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                "ORPort" -> {
                    orPort = ListenSpec.parse(value)
                    clientOnly = false
                }
                "ExtORPort" -> extOr = ListenSpec.parse(value)
                "DirPort" -> dirPort = ListenSpec.parse(value)
                "MetricsPort" -> metricsPort = ListenSpec.parse(value)
                "ExitRelay" -> exitRelay = value == "1"
                "ReducedExitPolicy" -> reducedExit = value == "1"
                "ExitPolicy" -> {
                    // Comma-separated or single rule; also accept bare "accept/reject …" as value.
                    value.split(',').map { it.trim() }.filter { it.isNotEmpty() }.forEach {
                        exitPolicies += it
                    }
                }
                "ExitPolicyRejectPrivate" -> exitPolicyRejectPrivate = value != "0"
                "ExitPolicyRejectLocalInterfaces" -> exitPolicyRejectLocalInterfaces = value != "0"
                "IPv6Exit" -> ipv6Exit = value == "1"
                "ExitNodes" -> exitNodes += value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                "MiddleNodes" -> middleNodes += value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                "BridgeAuthoritativeDir" -> bridgeAuthoritativeDir = value == "1"
                "BridgeDistribution" -> bridgeDistribution = value.trim().ifEmpty { "any" }
                "CircuitPadding" -> circuitPadding = value != "0"
                "ConnectionPadding" -> connectionPadding = AutoBool.parse(value)
                "ReducedPadding" -> reducedPadding = value == "1"
                "AssumeReachableIPv6" -> assumeReachableIpv6 = value == "1"
                "ClientUseIPv4" -> clientUseIpv4 = value != "0"
                "ClientUseIPv6" -> clientUseIpv6 = value != "0"
                "ClientRejectInternalAddresses" -> clientRejectInternalAddresses = value != "0"
                "HiddenServiceDir" -> {
                    flushHs()
                    currentHsDir = Path.of(value)
                }
                "HiddenServicePort" -> {
                    val vp = value.split(Regex("\\s+"))
                    currentHsPorts += HiddenServicePort(vp[0].toInt(), vp.getOrElse(1) { "127.0.0.1:${vp[0]}" })
                }
                "HiddenServicePoWDefensesEnabled" -> currentHsPow = value == "1"
                "HiddenServicePoWQueueRate" -> currentHsPowEffort = value.toIntOrNull() ?: currentHsPowEffort
                "HiddenServicePoWQueueBurst" -> currentHsPowBurst = value.toIntOrNull() ?: currentHsPowBurst
                "HiddenServiceMaxStreams" -> currentHsMaxStreams = value.toIntOrNull() ?: currentHsMaxStreams
                "HiddenServiceMaxStreamsCloseCircuit" -> currentHsMaxStreamsClose = value == "1"
                "HiddenServiceNumIntroductionPoints" ->
                    currentHsNumIntros = value.toIntOrNull()?.coerceIn(1, 20) ?: currentHsNumIntros
                "HiddenServiceVersion" -> currentHsVersion = value.toIntOrNull() ?: currentHsVersion
                "HiddenServiceEnableIntroDoSDefense" -> currentHsIntroDos = value == "1"
                "HiddenServiceEnableIntroDoSBurstPerSec" ->
                    currentHsIntroDosBurst = value.toIntOrNull() ?: currentHsIntroDosBurst
                "HiddenServiceEnableIntroDoSRatePerSec" -> {
                    currentHsIntroDosRate = value.toIntOrNull() ?: currentHsIntroDosRate
                    currentHsIntroRate = currentHsIntroDosRate * 60
                }
                "HiddenServiceOnionBalanceInstance" -> currentHsOnionBalance = value == "1"
                "HiddenServiceSingleHopMode" -> currentHsSingleHop = value == "1"
                "HiddenServiceNonAnonymousMode" -> currentHsNonAnon = value == "1"
                "HiddenServiceDirGroupReadable" -> currentHsDirGroupReadable = value == "1"
                "HiddenServiceExportCircuitID" ->
                    currentHsExportCircuitId = value.trim().ifEmpty { null }
                "IsolateClientAddr" -> if (value != "0") isolation += IsolationFlag.IsolateClientAddr
                "IsolateSOCKSAuth" -> if (value != "0") isolation += IsolationFlag.IsolateSOCKSAuth
                "IsolateClientProtocol" -> if (value != "0") isolation += IsolationFlag.IsolateClientProtocol
                "IsolateDestPort" -> if (value != "0") isolation += IsolationFlag.IsolateDestPort
                "IsolateDestAddr" -> if (value != "0") isolation += IsolationFlag.IsolateDestAddr
                "KeepAliveIsolateSOCKSAuth" ->
                    if (value != "0") isolation += IsolationFlag.KeepAliveIsolateSOCKSAuth
                "SafeLogging" -> safeLogging = value != "0"
                "NodeFamily", "MyFamily" ->
                    nodeFamily += value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                "CircuitDirtyTimeout" -> circuitDirtyTimeoutSec = value.toLongOrNull() ?: circuitDirtyTimeoutSec
                "CircuitUnusedTimeout", "MaxCircuitDirtiness" ->
                    circuitUnusedTimeoutSec = value.toLongOrNull() ?: circuitUnusedTimeoutSec
                "EnforceDistinctSubnets" -> enforceDistinctSubnets = value != "0"
                "EnforceDistinctCountries" -> enforceDistinctCountries = value != "0"
                "EnforceDistinctContinents" -> enforceDistinctContinents = value != "0"
                "CircuitAvoidRecentHops" -> circuitAvoidRecentHops = value != "0"
                "CircuitRecentHopHistorySize" ->
                    circuitRecentHopHistorySize =
                        value.toIntOrNull()?.coerceIn(1, 10_000) ?: circuitRecentHopHistorySize
                "DNSPort" -> dnsPort = ListenSpec.parse(value)
                "UdpTorGatewayPort" -> udpTorGatewayPort = ListenSpec.parse(value)
                "PublishServerDescriptor" -> publishServerDescriptor = value != "0"
                "ClientTransportPlugin" -> clientTransportPlugin = value
                "ServerTransportPlugin" -> serverTransportPlugin = value
                "ServerTransportListenAddr" -> serverTransportListenAddr += value
                "OptimisticData" -> optimisticData = value != "0"
                "TransPort" -> transPort = ListenSpec.parse(value.split(Regex("\\s+")).first())
                "VanguardsLiteEnabled" -> vanguardsLiteEnabled = value != "0"
                "OwningControllerProcess" -> owningControllerProcess = value.toLongOrNull()
                "OnionKeyLifetime" -> {
                    // torrc is duration like "28 days" — accept integer days or seconds
                    val n = value.trim().substringBefore(' ').toIntOrNull()
                    if (n != null) onionKeyRotationDays = if (value.contains("day", true)) n else (n / 86400).coerceAtLeast(1)
                }
                "HeartbeatPeriod" -> heartbeatPeriodSec = value.trim().substringBefore(' ').toLongOrNull() ?: heartbeatPeriodSec
                "Sandbox" -> sandbox = value == "1"
                "DisableNetwork" -> disableNetwork = value == "1"
                "Nickname" -> {
                    val n = value.trim().ifEmpty { nickname }
                    nickname = if (org.kotlintor.dir.Nickname.isLegalNickname(n)) n else nickname
                }
                "ContactInfo" -> contactInfo = value.trim().ifEmpty { contactInfo }
                "BandwidthRate" -> bandwidthRateBytes = parseBandwidth(value) ?: bandwidthRateBytes
                "BandwidthBurst" -> bandwidthBurstBytes = parseBandwidth(value) ?: bandwidthBurstBytes
                "CircuitBuildTimeout" ->
                    circuitBuildTimeoutSec = value.trim().substringBefore(' ').toLongOrNull() ?: circuitBuildTimeoutSec
                "MaxClientCircuitsPending" ->
                    maxClientCircuitsPending = value.toIntOrNull() ?: maxClientCircuitsPending
                "ConnLimit" -> connLimit = value.toIntOrNull() ?: connLimit
                "ConnLimitHighThresh" ->
                    processOpts = processOpts.copy(
                        connLimitHighThresh = value.toIntOrNull() ?: processOpts.connLimitHighThresh,
                    )
                "ConnLimitLowThresh" ->
                    processOpts = processOpts.copy(
                        connLimitLowThresh = value.toIntOrNull() ?: processOpts.connLimitLowThresh,
                    )
                "KeepalivePeriod" ->
                    keepalivePeriodSec = value.trim().substringBefore(' ').toLongOrNull() ?: keepalivePeriodSec
                "FetchDirInfoEarly" -> fetchDirInfoEarly = value == "1"
                "AvoidDiskWrites" -> avoidDiskWrites = value == "1"
                "DisableDebuggerAttachment" -> disableDebuggerAttachment = value != "0"
                "UseEntryGuards" -> useEntryGuards = value != "0"
                "NumEntryGuards", "NumPrimaryGuards" ->
                    numEntryGuards = value.toIntOrNull()?.coerceIn(1, 16) ?: numEntryGuards
                "EntryNodes" ->
                    entryNodes += value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                "StrictNodes" -> strictNodes = value == "1"
                "HTTPTunnelPort" -> httpTunnelPort = ListenSpec.parse(value.split(Regex("\\s+")).first())
                "LongLivedPorts" -> {
                    longLivedPorts = value.split(Regex("[,\\s]+"))
                        .mapNotNull { it.trim().toIntOrNull() }
                        .filter { it in 1..65535 }
                        .toSet()
                }
                "MapAddress" -> {
                    val parts = value.trim().split(Regex("\\s+"))
                    if (parts.size >= 2) mapAddress += parts[0] to parts[1]
                }
                "AccountingMax" -> accountingMaxBytes = parseBandwidth(value) ?: accountingMaxBytes
                "AccountingStart" -> {
                    // "month 1 00:00" / "day" / "week" — keep interval default; acknowledge richer later
                    if (value.contains("day", true)) accountingIntervalSec = 24 * 3600
                    else if (value.contains("week", true)) accountingIntervalSec = 7 * 24 * 3600L
                    else acknowledged["AccountingStart"] = value
                }
                "PathBiasDropGuards" -> {
                    pathBiasDropGuards = value == "1"
                    pathBiasOpts = pathBiasOpts.copy(dropGuards = pathBiasDropGuards)
                }
                "PathBiasCircThreshold" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        circThreshold = value.toIntOrNull() ?: pathBiasOpts.circThreshold,
                    )
                "PathBiasNoticeRate" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        noticeRate = value.toDoubleOrNull() ?: pathBiasOpts.noticeRate,
                    )
                "PathBiasWarnRate" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        warnRate = value.toDoubleOrNull() ?: pathBiasOpts.warnRate,
                    )
                "PathBiasExtremeRate" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        extremeRate = value.toDoubleOrNull() ?: pathBiasOpts.extremeRate,
                    )
                "PathBiasNoticeCountPercentile" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        noticeCountPercentile = value.toIntOrNull()
                            ?: pathBiasOpts.noticeCountPercentile,
                    )
                "PathBiasScaleThreshold" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        scaleThreshold = value.toIntOrNull() ?: pathBiasOpts.scaleThreshold,
                    )
                "PathBiasScaleUseThreshold" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        scaleUseThreshold = value.toIntOrNull()
                            ?: pathBiasOpts.scaleUseThreshold,
                    )
                "PathBiasUseThreshold" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        useThreshold = value.toIntOrNull() ?: pathBiasOpts.useThreshold,
                    )
                "PathBiasNoticeUseRate" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        noticeUseRate = value.toDoubleOrNull() ?: pathBiasOpts.noticeUseRate,
                    )
                "PathBiasExtremeUseRate" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        extremeUseRate = value.toDoubleOrNull() ?: pathBiasOpts.extremeUseRate,
                    )
                "PathBiasUseRate" ->
                    pathBiasOpts = pathBiasOpts.copy(
                        useRate = value.toDoubleOrNull() ?: pathBiasOpts.useRate,
                    )
                "GeoIPFile" -> geoIpFile = Path.of(value)
                "AutomapHostsOnResolve" -> automapHostsOnResolve = value == "1"
                "AutomapHostsSuffixes" ->
                    automapHostsSuffixes = value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                "VirtualAddrNetworkIPv4", "VirtualAddrNetwork" ->
                    virtualAddrNetworkIpv4 = value.trim().ifEmpty { virtualAddrNetworkIpv4 }
                "MaxOnionQueueDelay" ->
                    maxOnionQueueDelayMs = value.trim().substringBefore(' ').toLongOrNull() ?: maxOnionQueueDelayMs
                "CircuitPriorityHalflifeMsec" ->
                    circuitPriorityHalflifeMsec = value.toLongOrNull() ?: circuitPriorityHalflifeMsec
                "CircuitPriorityHalflife" -> {
                    // seconds (float-ish) → msec
                    val sec = value.trim().substringBefore(' ').toDoubleOrNull()
                    if (sec != null) circuitPriorityHalflifeMsec = (sec * 1000.0).toLong()
                }
                "DoSCircuitCreationEnabled" ->
                    dosOpts = dosOpts.copy(circuitCreationEnabled = value == "1")
                "DoSCircuitCreationMinConnections" ->
                    dosOpts = dosOpts.copy(
                        circuitCreationMinConnections = value.toIntOrNull()
                            ?: dosOpts.circuitCreationMinConnections,
                    )
                "DoSCircuitCreationRate" ->
                    dosOpts = dosOpts.copy(
                        circuitCreationRate = value.toIntOrNull() ?: dosOpts.circuitCreationRate,
                    )
                "DoSCircuitCreationBurst" ->
                    dosOpts = dosOpts.copy(
                        circuitCreationBurst = value.toIntOrNull() ?: dosOpts.circuitCreationBurst,
                    )
                "DoSConnectionEnabled" ->
                    dosOpts = dosOpts.copy(connectionEnabled = value == "1")
                "DoSConnectionMaxConcurrentCount" ->
                    dosOpts = dosOpts.copy(
                        connectionMaxConcurrent = value.toIntOrNull() ?: dosOpts.connectionMaxConcurrent,
                    )
                "DoSStreamCreationEnabled" ->
                    dosOpts = dosOpts.copy(streamCreationEnabled = value == "1")
                "DoSStreamCreationRate" ->
                    dosOpts = dosOpts.copy(
                        streamCreationRate = value.toIntOrNull() ?: dosOpts.streamCreationRate,
                    )
                "DoSStreamCreationBurst" ->
                    dosOpts = dosOpts.copy(
                        streamCreationBurst = value.toIntOrNull() ?: dosOpts.streamCreationBurst,
                    )
                "DoSRefuseSingleHopClientRendezvous" ->
                    dosOpts = dosOpts.copy(refuseSingleHopClientRendezvous = value != "0")
                "NewCircuitPeriod" ->
                    newCircuitPeriodSec = value.trim().substringBefore(' ').toLongOrNull() ?: newCircuitPeriodSec
                "LearnCircuitBuildTimeout" -> learnCircuitBuildTimeout = value != "0"
                "Schedulers" -> {
                    val parsed = org.kotlintor.link.ChannelScheduler.parseList(value)
                    if (parsed.isNotEmpty()) schedulers = parsed
                }
                "AuthoritativeDirectory" -> authoritativeDirectory = value == "1"
                "V3AuthoritativeDirectory" -> v3AuthoritativeDirectory = value == "1"
                "TestingTorNetwork" -> testingTorNetwork = value == "1"
                "UseMicrodescriptors" -> useMicrodescriptors = value != "0"
                "FetchUselessDescriptors" -> fetchUselessDescriptors = value == "1"
                "DownloadExtraInfo" -> downloadExtraInfo = value == "1"
                "AssumeReachable" -> assumeReachable = value == "1"
                "BridgeRelay" -> bridgeRelay = value == "1"
                "ExtendAllowPrivateAddresses" -> extendAllowPrivateAddresses = value == "1"
                "DirAllowPrivateAddresses" -> dirAllowPrivateAddresses = value == "1"
                "RefuseUnknownExits" -> refuseUnknownExits = AutoBool.parse(value)
                "FetchDirInfoExtraEarly" -> {
                    fetchDirInfoExtraEarly = value == "1"
                    if (fetchDirInfoExtraEarly) fetchDirInfoEarly = true
                }
                "CellStatistics" -> statsOpts = statsOpts.copy(cellStatistics = value == "1")
                "PaddingStatistics" -> statsOpts = statsOpts.copy(paddingStatistics = value == "1")
                "DirReqStatistics" -> statsOpts = statsOpts.copy(dirReqStatistics = value == "1")
                "EntryStatistics" -> statsOpts = statsOpts.copy(entryStatistics = value == "1")
                "ExitPortStatistics" -> statsOpts = statsOpts.copy(exitPortStatistics = value == "1")
                "ConnDirectionStatistics" -> statsOpts = statsOpts.copy(connDirectionStatistics = value == "1")
                "HiddenServiceStatistics" -> statsOpts = statsOpts.copy(hiddenServiceStatistics = value == "1")
                "ExtraInfoStatistics" -> statsOpts = statsOpts.copy(extraInfoStatistics = value != "0")
                "MainloopStats" -> statsOpts = statsOpts.copy(mainloopStats = value == "1")
                "OverloadStatistics" -> statsOpts = statsOpts.copy(overloadStatistics = value == "1")
                "GuardLifetime" -> {
                    val days = value.trim().substringBefore(' ').toLongOrNull()
                    if (days != null) guardLifetimeDays = days
                }
                "NumDirectoryGuards" -> numDirectoryGuards = value.toIntOrNull() ?: numDirectoryGuards
                "GuardsKeepDesc" -> guardsKeepDesc = value != "0"
                "DirAuthority" ->
                    org.kotlintor.dir.DirAuthorityConfig.parseDirAuthority(value)?.let { dirAuthorities += it }
                "FallbackDir" ->
                    org.kotlintor.dir.DirAuthorityConfig.parseFallbackDir(value)?.let { fallbackDirs += it }
                "UseDefaultFallbackDirs" -> useDefaultFallbackDirs = value != "0"
                "FetchHidServDescriptors" -> fetchHidServDescriptors = value != "0"
                "FetchServerDescriptors" -> fetchServerDescriptors = value != "0"
                "ClientDNSRejectInternalAddresses" -> clientDnsRejectInternalAddresses = value != "0"
                "DNSSECMode" -> dnssecMode = org.kotlintor.net.dns.DnssecMode.parse(value)
                "DNSSECRecursive" -> dnssecRecursive = value.trim()
                "DNSSECTrustAnchorFile" -> dnssecTrustAnchorFile = Path.of(value.trim())
                "Address" -> address = value.trim().ifEmpty { null }
                "OutboundBindAddress" -> outboundBind = value.trim().ifEmpty { null }
                "OutboundBindAddressOR" -> outboundBindOr = value.trim().ifEmpty { null }
                "OutboundBindAddressExit" -> outboundBindExit = value.trim().ifEmpty { null }
                "OutboundBindAddressPT" -> outboundBindPt = value.trim().ifEmpty { null }
                "FascistFirewall" -> fascistFirewall = value == "1"
                "FirewallPorts" ->
                    firewallPorts += value.split(',').mapNotNull { it.trim().toIntOrNull() }
                "ReachableORAddresses" -> reachableOr += value
                "ReachableDirAddresses" -> reachableDir += value
                "ReachableAddresses" -> reachableAny += value
                "SafeSocks" -> safeSocks = value == "1"
                "TestSocks" -> testSocks = value == "1"
                "WarnUnsafeSocks" -> warnUnsafeSocks = value != "0"
                "SocksTimeout" ->
                    socksTimeoutSec = value.trim().substringBefore(' ').toLongOrNull() ?: socksTimeoutSec
                "MaxAdvertisedBandwidth" ->
                    maxAdvertisedBandwidthBytes = parseBandwidth(value) ?: maxAdvertisedBandwidthBytes
                "RelayBandwidthRate" ->
                    relayBandwidthRateBytes = parseBandwidth(value) ?: relayBandwidthRateBytes
                "RelayBandwidthBurst" ->
                    relayBandwidthBurstBytes = parseBandwidth(value) ?: relayBandwidthBurstBytes
                "PerConnBWRate" ->
                    perConnBwRateBytes = parseBandwidth(value) ?: perConnBwRateBytes
                "PerConnBWBurst" ->
                    perConnBwBurstBytes = parseBandwidth(value) ?: perConnBwBurstBytes
                "CookieAuthFile" -> cookieAuthFile = Path.of(value)
                "KeyDirectory" -> keyDirectory = Path.of(value)
                "CacheDirectory" -> cacheDirectory = Path.of(value)
                "PublishHidServDescriptors" -> publishHidServDescriptors = value != "0"
                "Padding" -> padding = AutoBool.parse(value)
                "CircuitIdleTimeout" ->
                    circuitIdleTimeoutSec = value.trim().substringBefore(' ').toLongOrNull()
                        ?: circuitIdleTimeoutSec
                "CircuitStreamTimeout" ->
                    circuitStreamTimeoutSec = value.trim().substringBefore(' ').toLongOrNull()
                        ?: circuitStreamTimeoutSec
                "PidFile" -> processOpts = processOpts.copy(pidFile = Path.of(value))
                "RunAsDaemon" -> processOpts = processOpts.copy(runAsDaemon = value == "1")
                "User" -> processOpts = processOpts.copy(user = value.trim().ifEmpty { null })
                "NumCPUs" -> processOpts = processOpts.copy(numCpus = value.toIntOrNull() ?: processOpts.numCpus)
                "OfflineMasterKey" -> processOpts = processOpts.copy(offlineMasterKey = value == "1")
                "OnionKeyGracePeriod" ->
                    processOpts = processOpts.copy(
                        onionKeyGracePeriodDays = value.trim().substringBefore(' ').toIntOrNull()
                            ?: processOpts.onionKeyGracePeriodDays,
                    )
                "SigningKeyLifetime" ->
                    processOpts = processOpts.copy(
                        signingKeyLifetimeDays = value.trim().substringBefore(' ').toIntOrNull()
                            ?: processOpts.signingKeyLifetimeDays,
                    )
                "ShutdownWaitLength" ->
                    processOpts = processOpts.copy(
                        shutdownWaitLengthSec = value.trim().substringBefore(' ').toLongOrNull()
                            ?: processOpts.shutdownWaitLengthSec,
                    )
                "NoExec" -> processOpts = processOpts.copy(noExec = value == "1")
                "ConstrainedSockets" -> processOpts = processOpts.copy(constrainedSockets = value == "1")
                "ConstrainedSockSize" ->
                    processOpts = processOpts.copy(
                        constrainedSockSize = value.toIntOrNull() ?: processOpts.constrainedSockSize,
                    )
                "MaxMemInQueues" ->
                    processOpts = processOpts.copy(
                        maxMemInQueuesBytes = parseBandwidth(value) ?: processOpts.maxMemInQueuesBytes,
                    )
                "MaxMemInQueuesLowThreshold" ->
                    processOpts = processOpts.copy(
                        maxMemInQueuesLowThresholdBytes =
                            parseBandwidth(value) ?: processOpts.maxMemInQueuesLowThresholdBytes,
                    )
                "MaxConsensusAgeForDiffs" ->
                    processOpts = processOpts.copy(
                        maxConsensusAgeForDiffsSec = value.trim().substringBefore(' ').toLongOrNull()
                            ?: processOpts.maxConsensusAgeForDiffsSec,
                    )
                "ProtocolWarnings" -> processOpts = processOpts.copy(protocolWarnings = value == "1")
                "AllowNonRFC953Hostnames" ->
                    processOpts = processOpts.copy(allowNonRfc953Hostnames = value == "1")
                "ClientPreferIPv6ORPort" ->
                    processOpts = processOpts.copy(clientPreferIpv6OrPort = value == "1")
                "ClientPreferIPv6DirPort" ->
                    processOpts = processOpts.copy(clientPreferIpv6DirPort = value == "1")
                "ReducedCircuitPadding" ->
                    processOpts = processOpts.copy(reducedCircuitPadding = value == "1")
                "ReducedConnectionPadding" ->
                    processOpts = processOpts.copy(reducedConnectionPadding = value == "1")
                "UpdateBridgesFromAuthority" ->
                    processOpts = processOpts.copy(updateBridgesFromAuthority = value == "1")
                "VirtualAddrNetworkIPv6" ->
                    processOpts = processOpts.copy(
                        virtualAddrNetworkIpv6 = value.trim().ifEmpty { processOpts.virtualAddrNetworkIpv6 },
                    )
                "AccountingRule" ->
                    processOpts = processOpts.copy(accountingRule = value.trim().lowercase().ifEmpty { "max" })
                "DirAuthorityFallbackRate" ->
                    processOpts = processOpts.copy(
                        dirAuthorityFallbackRate = value.toDoubleOrNull() ?: processOpts.dirAuthorityFallbackRate,
                    )
                "DirPortFrontPage" -> processOpts = processOpts.copy(dirPortFrontPage = Path.of(value))
                "ExtORPortCookieAuthFile" ->
                    processOpts = processOpts.copy(extOrPortCookieAuthFile = Path.of(value))
                "ControlPortWriteToFile" ->
                    processOpts = processOpts.copy(controlPortWriteToFile = Path.of(value))
                "ControlPortFileGroupReadable" ->
                    processOpts = processOpts.copy(controlPortFileGroupReadable = value == "1")
                "CookieAuthFileGroupReadable" ->
                    processOpts = processOpts.copy(cookieAuthFileGroupReadable = value == "1")
                "DataDirectoryGroupReadable" ->
                    processOpts = processOpts.copy(dataDirectoryGroupReadable = value == "1")
                "CacheDirectoryGroupReadable" ->
                    processOpts = processOpts.copy(cacheDirectoryGroupReadable = value == "1")
                "KeyDirectoryGroupReadable" ->
                    processOpts = processOpts.copy(keyDirectoryGroupReadable = value == "1")
                "ExtORPortCookieAuthFileGroupReadable" ->
                    processOpts = processOpts.copy(extOrPortCookieAuthFileGroupReadable = value == "1")
                "AddressDisableIPv6" ->
                    processOpts = processOpts.copy(addressDisableIPv6 = value == "1")
                "LogTimeGranularity" ->
                    processOpts = processOpts.copy(
                        logTimeGranularityMs = value.toIntOrNull() ?: processOpts.logTimeGranularityMs,
                    )
                "ControlSocketsGroupWritable" ->
                    processOpts = processOpts.copy(controlSocketsGroupWritable = value == "1")
                "MetricsPortPolicy" -> processOpts = processOpts.copy(metricsPortPolicy = value)
                "SocksPolicy" ->
                    processOpts = processOpts.copy(
                        socksPolicyLines = processOpts.socksPolicyLines + value,
                    )
                "SessionGroup" ->
                    processOpts = processOpts.copy(sessionGroup = value.toIntOrNull() ?: processOpts.sessionGroup)
                "OwningControllerFD" ->
                    processOpts = processOpts.copy(owningControllerFd = value.toLongOrNull())
                "SyslogIdentityTag" -> processOpts = processOpts.copy(syslogIdentityTag = value)
                "AndroidIdentityTag" -> processOpts = processOpts.copy(androidIdentityTag = value)
                "Log" -> {
                    val toks = value.trim().split(Regex("\\s+"))
                    when (toks.firstOrNull()?.uppercase()) {
                        "DEBUG" -> logLevel = LogLevel.DEBUG
                        "INFO" -> logLevel = LogLevel.INFO
                        "NOTICE" -> logLevel = LogLevel.NOTICE
                        "WARN", "WARNING" -> logLevel = LogLevel.WARN
                        "ERR", "ERROR" -> logLevel = LogLevel.ERR
                    }
                    val fileIdx = toks.indexOfFirst { it.equals("file", true) }
                    if (fileIdx >= 0 && fileIdx + 1 < toks.size) {
                        processOpts = processOpts.copy(logFile = Path.of(toks[fileIdx + 1]))
                    }
                }
                "LogMessageDomains" -> processOpts = processOpts.copy(logMessageDomains = value == "1")
                "KeepBindCapabilities" -> processOpts = processOpts.copy(keepBindCapabilities = value == "1")
                "DisableAllSwap" -> processOpts = processOpts.copy(disableAllSwap = value == "1")
                "HardwareAccel" -> processOpts = processOpts.copy(hardwareAccel = value == "1")
                "AccelName" -> processOpts = processOpts.copy(accelName = value)
                "AccelDir" -> processOpts = processOpts.copy(accelDir = Path.of(value))
                "CountPrivateBandwidth" -> processOpts = processOpts.copy(countPrivateBandwidth = value == "1")
                "FetchV2Networkstatus" -> processOpts = processOpts.copy(fetchV2Networkstatus = value == "1")
                "BridgeRecordUsageByCountry" ->
                    processOpts = processOpts.copy(bridgeRecordUsageByCountry = value == "1")
                "NATDPort" -> processOpts = processOpts.copy(natdPort = ListenSpec.parse(value))
                "TransProxyType" -> processOpts = processOpts.copy(transProxyType = value.trim())
                "DNSListenAddress" -> processOpts = processOpts.copy(dnsListenAddress = value)
                "ServerTransportOptions" ->
                    processOpts = processOpts.copy(
                        serverTransportOptions = processOpts.serverTransportOptions + value,
                    )
                "DoSCircuitCreationDefenseType" ->
                    processOpts = processOpts.copy(
                        dosCircuitCreationDefenseType = value.toIntOrNull()
                            ?: processOpts.dosCircuitCreationDefenseType,
                    )
                "DoSConnectionDefenseType" ->
                    processOpts = processOpts.copy(
                        dosConnectionDefenseType = value.toIntOrNull()
                            ?: processOpts.dosConnectionDefenseType,
                    )
                "DoSStreamCreationDefenseType" ->
                    processOpts = processOpts.copy(
                        dosStreamCreationDefenseType = value.toIntOrNull()
                            ?: processOpts.dosStreamCreationDefenseType,
                    )
                "DoSCircuitCreationDefenseTimePeriod" ->
                    processOpts = processOpts.copy(
                        dosCircuitCreationDefenseTimePeriodSec =
                            value.trim().substringBefore(' ').toLongOrNull()
                                ?: processOpts.dosCircuitCreationDefenseTimePeriodSec,
                    )
                "AllDirActionsPrivate" ->
                    runtimeOpts = runtimeOpts.copy(allDirActionsPrivate = value == "1")
                "AlwaysCongestionControl" ->
                    runtimeOpts = runtimeOpts.copy(alwaysCongestionControl = value == "1")
                "CircuitsAvailableTimeout" ->
                    runtimeOpts = runtimeOpts.copy(
                        circuitsAvailableTimeoutSec = value.trim().substringBefore(' ').toLongOrNull()
                            ?: runtimeOpts.circuitsAvailableTimeoutSec,
                    )
                "ConfluxEnabled" ->
                    runtimeOpts = runtimeOpts.copy(confluxEnabled = value != "0")
                "ConfluxClientUX" ->
                    runtimeOpts = runtimeOpts.copy(
                        confluxClientUx = value.toIntOrNull() ?: runtimeOpts.confluxClientUx,
                    )
                "DirCache" -> runtimeOpts = runtimeOpts.copy(dirCache = value != "0")
                "DisableOOSCheck" -> runtimeOpts = runtimeOpts.copy(disableOosCheck = value == "1")
                "DisablePredictedCircuits" ->
                    runtimeOpts = runtimeOpts.copy(disablePredictedCircuits = value == "1")
                "DisableSignalHandlers" ->
                    runtimeOpts = runtimeOpts.copy(disableSignalHandlers = value == "1")
                "DormantCanceledByStartup" ->
                    runtimeOpts = runtimeOpts.copy(dormantCanceledByStartup = value == "1")
                "DormantClientTimeout" ->
                    runtimeOpts = runtimeOpts.copy(
                        dormantClientTimeoutSec = value.trim().substringBefore(' ').toLongOrNull()
                            ?: runtimeOpts.dormantClientTimeoutSec,
                    )
                "DormantOnFirstStartup" ->
                    runtimeOpts = runtimeOpts.copy(dormantOnFirstStartup = value == "1")
                "DormantTimeoutDisabledByIdleStreams" ->
                    runtimeOpts = runtimeOpts.copy(dormantTimeoutDisabledByIdleStreams = value != "0")
                "DormantTimeoutEnabled" ->
                    runtimeOpts = runtimeOpts.copy(dormantTimeoutEnabled = value != "0")
                "ExtendByEd25519ID" ->
                    runtimeOpts = runtimeOpts.copy(extendByEd25519Id = value != "0")
                "GeoIPExcludeUnknown" ->
                    runtimeOpts = runtimeOpts.copy(geoIpExcludeUnknown = value == "1")
                "HTTPProxy" -> runtimeOpts = runtimeOpts.copy(httpProxy = value)
                "HTTPSProxy" -> runtimeOpts = runtimeOpts.copy(httpsProxy = value)
                "Socks4Proxy" -> runtimeOpts = runtimeOpts.copy(socks4Proxy = value)
                "Socks5Proxy" -> runtimeOpts = runtimeOpts.copy(socks5Proxy = value)
                "TCPProxy" -> runtimeOpts = runtimeOpts.copy(tcpProxy = value)
                "TCPProxyProtocol" -> runtimeOpts = runtimeOpts.copy(tcpProxyProtocol = value.trim())
                "KISTSchedRunInterval" ->
                    runtimeOpts = runtimeOpts.copy(
                        kistSchedRunIntervalMs = value.toIntOrNull() ?: runtimeOpts.kistSchedRunIntervalMs,
                    )
                "KISTSockBufSizeFactor" ->
                    runtimeOpts = runtimeOpts.copy(
                        kistSockBufSizeFactor = value.toDoubleOrNull() ?: runtimeOpts.kistSockBufSizeFactor,
                    )
                "LeaveStreamsUnattached" ->
                    runtimeOpts = runtimeOpts.copy(leaveStreamsUnattached = value == "1")
                "ManualOnionKeyRotation" ->
                    runtimeOpts = runtimeOpts.copy(manualOnionKeyRotation = value == "1")
                "MaxHSDirCacheBytes" ->
                    runtimeOpts = runtimeOpts.copy(
                        maxHsDirCacheBytes = value.toLongOrNull() ?: runtimeOpts.maxHsDirCacheBytes,
                    )
                "MaxUnparseableDescSizeToLog" ->
                    runtimeOpts = runtimeOpts.copy(
                        maxUnparseableDescSizeToLog =
                            value.toLongOrNull() ?: runtimeOpts.maxUnparseableDescSizeToLog,
                    )
                "PathsNeededToBuildCircuits" ->
                    runtimeOpts = runtimeOpts.copy(
                        pathsNeededToBuildCircuits =
                            value.toDoubleOrNull() ?: runtimeOpts.pathsNeededToBuildCircuits,
                    )
                "ReconfigDropsBridgeDescs" ->
                    runtimeOpts = runtimeOpts.copy(reconfigDropsBridgeDescs = value == "1")
                "ReevaluateExitPolicy" ->
                    runtimeOpts = runtimeOpts.copy(reevaluateExitPolicy = value == "1")
                "ReloadTorrcOnSIGHUP" ->
                    runtimeOpts = runtimeOpts.copy(reloadTorrcOnSighup = value != "0")
                "RephistTrackTime" ->
                    runtimeOpts = runtimeOpts.copy(
                        rephistTrackTimeSec = value.trim().substringBefore(' ').toLongOrNull()
                            ?: runtimeOpts.rephistTrackTimeSec,
                    )
                "SSLKeyLifetime" ->
                    runtimeOpts = runtimeOpts.copy(
                        sslKeyLifetimeDays = value.toIntOrNull() ?: runtimeOpts.sslKeyLifetimeDays,
                    )
                "SbwsExit" -> runtimeOpts = runtimeOpts.copy(sbwsExit = value == "1")
                "TokenBucketRefillInterval" ->
                    runtimeOpts = runtimeOpts.copy(
                        tokenBucketRefillIntervalMs =
                            value.toIntOrNull() ?: runtimeOpts.tokenBucketRefillIntervalMs,
                    )
                "TrackHostExitsExpire" ->
                    runtimeOpts = runtimeOpts.copy(
                        trackHostExitsExpireSec =
                            value.trim().substringBefore(' ').toLongOrNull()
                                ?: runtimeOpts.trackHostExitsExpireSec,
                    )
                "TruncateLogFile" -> runtimeOpts = runtimeOpts.copy(truncateLogFile = value == "1")
                "UnixSocksGroupWritable" ->
                    runtimeOpts = runtimeOpts.copy(unixSocksGroupWritable = value == "1")
                "UseGuardFraction" -> runtimeOpts = runtimeOpts.copy(useGuardFraction = value == "1")
                "V3AuthVotingInterval" ->
                    runtimeOpts = runtimeOpts.copy(
                        v3AuthVotingIntervalSec =
                            value.toIntOrNull() ?: runtimeOpts.v3AuthVotingIntervalSec,
                    )
                "V3AuthVoteDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        v3AuthVoteDelaySec = value.toIntOrNull() ?: runtimeOpts.v3AuthVoteDelaySec,
                    )
                "V3AuthDistDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        v3AuthDistDelaySec = value.toIntOrNull() ?: runtimeOpts.v3AuthDistDelaySec,
                    )
                "V3AuthNIntervalsValid" ->
                    runtimeOpts = runtimeOpts.copy(
                        v3AuthNIntervalsValid =
                            value.toIntOrNull() ?: runtimeOpts.v3AuthNIntervalsValid,
                    )
                "V3AuthUseLegacyKey" ->
                    runtimeOpts = runtimeOpts.copy(v3AuthUseLegacyKey = value == "1")
                "ClientBootstrapConsensusAuthorityDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        clientBootstrapConsensusAuthorityDownloadInitialDelay =
                            value.toIntOrNull()
                                ?: runtimeOpts.clientBootstrapConsensusAuthorityDownloadInitialDelay,
                    )
                "ClientBootstrapConsensusAuthorityOnlyDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        clientBootstrapConsensusAuthorityOnlyDownloadInitialDelay =
                            value.toIntOrNull()
                                ?: runtimeOpts.clientBootstrapConsensusAuthorityOnlyDownloadInitialDelay,
                    )
                "ClientBootstrapConsensusFallbackDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        clientBootstrapConsensusFallbackDownloadInitialDelay =
                            value.toIntOrNull()
                                ?: runtimeOpts.clientBootstrapConsensusFallbackDownloadInitialDelay,
                    )
                "ClientBootstrapConsensusMaxInProgressTries" ->
                    runtimeOpts = runtimeOpts.copy(
                        clientBootstrapConsensusMaxInProgressTries =
                            value.toIntOrNull()
                                ?: runtimeOpts.clientBootstrapConsensusMaxInProgressTries,
                    )
                "CompiledProofOfWorkHash" ->
                    runtimeOpts = runtimeOpts.copy(
                        compiledProofOfWorkHash =
                            value.toIntOrNull() ?: runtimeOpts.compiledProofOfWorkHash,
                    )
                "AllFamilyIdsExpected" ->
                    runtimeOpts = runtimeOpts.copy(allFamilyIdsExpected = value == "1")
                "TestingAuthKeyLifetime" ->
                    runtimeOpts = runtimeOpts.copy(testingAuthKeyLifetime = value)
                "TestingAuthKeySlop" ->
                    runtimeOpts = runtimeOpts.copy(testingAuthKeySlop = value)
                "TestingBridgeBootstrapDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingBridgeBootstrapDownloadInitialDelay =
                            value.toIntOrNull()
                                ?: runtimeOpts.testingBridgeBootstrapDownloadInitialDelay,
                    )
                "TestingBridgeDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingBridgeDownloadInitialDelay =
                            value.toIntOrNull() ?: runtimeOpts.testingBridgeDownloadInitialDelay,
                    )
                "TestingClientConsensusDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingClientConsensusDownloadInitialDelay =
                            value.toIntOrNull()
                                ?: runtimeOpts.testingClientConsensusDownloadInitialDelay,
                    )
                "TestingClientDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingClientDownloadInitialDelay =
                            value.toIntOrNull() ?: runtimeOpts.testingClientDownloadInitialDelay,
                    )
                "TestingClientMaxIntervalWithoutRequest" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingClientMaxIntervalWithoutRequest =
                            value.toIntOrNull()
                                ?: runtimeOpts.testingClientMaxIntervalWithoutRequest,
                    )
                "TestingDirConnectionMaxStall" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingDirConnectionMaxStall =
                            value.toIntOrNull() ?: runtimeOpts.testingDirConnectionMaxStall,
                    )
                "TestingEnableCellStatsEvent" ->
                    runtimeOpts = runtimeOpts.copy(testingEnableCellStatsEvent = value == "1")
                "TestingEnableConnBwEvent" ->
                    runtimeOpts = runtimeOpts.copy(testingEnableConnBwEvent = value == "1")
                "TestingLinkCertLifetime" ->
                    runtimeOpts = runtimeOpts.copy(testingLinkCertLifetime = value)
                "TestingLinkKeySlop" ->
                    runtimeOpts = runtimeOpts.copy(testingLinkKeySlop = value)
                "TestingMinTimeToReportBandwidth" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingMinTimeToReportBandwidth =
                            value.toIntOrNull() ?: runtimeOpts.testingMinTimeToReportBandwidth,
                    )
                "TestingServerConsensusDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingServerConsensusDownloadInitialDelay =
                            value.toIntOrNull()
                                ?: runtimeOpts.testingServerConsensusDownloadInitialDelay,
                    )
                "TestingServerDownloadInitialDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingServerDownloadInitialDelay =
                            value.toIntOrNull() ?: runtimeOpts.testingServerDownloadInitialDelay,
                    )
                "TestingSigningKeySlop" ->
                    runtimeOpts = runtimeOpts.copy(testingSigningKeySlop = value)
                "TestingV3AuthInitialDistDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingV3AuthInitialDistDelay =
                            value.toIntOrNull() ?: runtimeOpts.testingV3AuthInitialDistDelay,
                    )
                "TestingV3AuthInitialVoteDelay" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingV3AuthInitialVoteDelay =
                            value.toIntOrNull() ?: runtimeOpts.testingV3AuthInitialVoteDelay,
                    )
                "TestingV3AuthInitialVotingInterval" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingV3AuthInitialVotingInterval =
                            value.toIntOrNull()
                                ?: runtimeOpts.testingV3AuthInitialVotingInterval,
                    )
                "TestingV3AuthVotingStartOffset" ->
                    runtimeOpts = runtimeOpts.copy(
                        testingV3AuthVotingStartOffset =
                            value.toIntOrNull() ?: runtimeOpts.testingV3AuthVotingStartOffset,
                    )
                "ServerDNSResolvConfFile" ->
                    serverDnsOpts = serverDnsOpts.copy(resolvConfFile = Path.of(value))
                "ServerDNSAllowBrokenConfig" ->
                    serverDnsOpts = serverDnsOpts.copy(allowBrokenConfig = value == "1")
                "ServerDNSSearchDomains" ->
                    serverDnsOpts = serverDnsOpts.copy(searchDomains = value == "1")
                "ServerDNSDetectHijacking" ->
                    serverDnsOpts = serverDnsOpts.copy(detectHijacking = value != "0")
                "ServerDNSTestAddresses" ->
                    serverDnsOpts = serverDnsOpts.copy(
                        testAddresses = value.split(',').map { it.trim() }.filter { it.isNotEmpty() },
                    )
                "ServerDNSAllowNonRFC953Hostnames" ->
                    serverDnsOpts = serverDnsOpts.copy(allowNonRfc953Hostnames = value == "1")
                "ServerDNSRandomizeCase" ->
                    serverDnsOpts = serverDnsOpts.copy(randomizeCase = value != "0")
                else -> if (key.isNotEmpty() && !key.startsWith("%")) {
                    if (TorrcManpageKeys.isKnown(key)) acknowledged[key] = value
                    else unrecognized[key] = value
                }
            }
        }
        flushHs()
        if (fetchDirInfoExtraEarly && !fetchDirInfoEarly) {
            fetchDirInfoEarly = true
        }
        return TorConfig(
            dataDirectory = dataDirectory,
            socksPorts = socks.ifEmpty { listOf(ListenSpec("127.0.0.1", 9050)) },
            controlPorts = control.ifEmpty { listOf(ListenSpec("127.0.0.1", 9051)) },
            controlSockets = controlSocks,
            cookieAuthentication = cookieAuth,
            hashedControlPassword = hashed,
            clientOnly = clientOnly,
            useBridges = useBridges,
            bridges = bridges,
            excludeNodes = exclude,
            excludeExitNodes = excludeExit,
            orPort = orPort,
            extOrPort = extOr,
            dirPort = dirPort,
            metricsPort = metricsPort,
            exitRelay = exitRelay,
            reducedExitPolicy = reducedExit,
            exitPolicyLines = exitPolicies,
            exitPolicyRejectPrivate = exitPolicyRejectPrivate,
            exitPolicyRejectLocalInterfaces = exitPolicyRejectLocalInterfaces,
            ipv6Exit = ipv6Exit,
            exitNodes = exitNodes.toList(),
            middleNodes = middleNodes.toList(),
            bridgeAuthoritativeDir = bridgeAuthoritativeDir,
            bridgeDistribution = bridgeDistribution,
            circuitPadding = circuitPadding,
            connectionPadding = connectionPadding,
            reducedPadding = reducedPadding,
            assumeReachableIpv6 = assumeReachableIpv6,
            statsOptions = statsOpts,
            guardLifetimeDays = guardLifetimeDays,
            numDirectoryGuards = numDirectoryGuards,
            guardsKeepDesc = guardsKeepDesc,
            dirAuthorities = dirAuthorities.toList(),
            fallbackDirs = fallbackDirs.toList(),
            useDefaultFallbackDirs = useDefaultFallbackDirs,
            fetchHidServDescriptors = fetchHidServDescriptors,
            fetchServerDescriptors = fetchServerDescriptors,
            clientDnsRejectInternalAddresses = clientDnsRejectInternalAddresses,
            dnssecMode = dnssecMode,
            dnssecRecursive = dnssecRecursive,
            dnssecTrustAnchorFile = dnssecTrustAnchorFile,
            address = address,
            outboundBindAddress = outboundBind,
            outboundBindAddressOr = outboundBindOr,
            outboundBindAddressExit = outboundBindExit,
            outboundBindAddressPt = outboundBindPt,
            fascistFirewall = fascistFirewall,
            firewallPorts = firewallPorts.toSet(),
            reachableOrAddresses = reachableOr.toList(),
            reachableDirAddresses = reachableDir.toList(),
            reachableAddresses = reachableAny.toList(),
            safeSocks = safeSocks,
            testSocks = testSocks,
            warnUnsafeSocks = warnUnsafeSocks,
            safeSocksAllowIpLiterals = false,
            socksTimeoutSec = socksTimeoutSec,
            maxAdvertisedBandwidthBytes = maxAdvertisedBandwidthBytes,
            relayBandwidthRateBytes = relayBandwidthRateBytes,
            relayBandwidthBurstBytes = relayBandwidthBurstBytes,
            perConnBwRateBytes = perConnBwRateBytes,
            perConnBwBurstBytes = perConnBwBurstBytes,
            cookieAuthFile = cookieAuthFile,
            keyDirectory = keyDirectory,
            cacheDirectory = cacheDirectory,
            publishHidServDescriptors = publishHidServDescriptors,
            padding = padding,
            circuitIdleTimeoutSec = circuitIdleTimeoutSec,
            circuitStreamTimeoutSec = circuitStreamTimeoutSec,
            process = processOpts,
            serverDns = serverDnsOpts,
            hiddenServices = hs,
            safeLogging = safeLogging,
            logLevel = logLevel,
            isolationFlags = isolation,
            clientUseIpv4 = clientUseIpv4,
            clientUseIpv6 = clientUseIpv6,
            clientRejectInternalAddresses = clientRejectInternalAddresses,
            nodeFamily = nodeFamily,
            circuitDirtyTimeoutSec = circuitDirtyTimeoutSec,
            circuitUnusedTimeoutSec = circuitUnusedTimeoutSec,
            enforceDistinctSubnets = enforceDistinctSubnets,
            enforceDistinctCountries = enforceDistinctCountries,
            enforceDistinctContinents = enforceDistinctContinents,
            circuitAvoidRecentHops = circuitAvoidRecentHops,
            circuitRecentHopHistorySize = circuitRecentHopHistorySize,
            dnsPort = dnsPort,
            udpTorGatewayPort = udpTorGatewayPort,
            publishServerDescriptor = publishServerDescriptor,
            clientTransportPlugin = clientTransportPlugin,
            serverTransportPlugin = serverTransportPlugin,
            serverTransportListenAddr = serverTransportListenAddr.toList(),
            optimisticData = optimisticData,
            transPort = transPort,
            vanguardsLiteEnabled = vanguardsLiteEnabled,
            owningControllerProcess = owningControllerProcess,
            onionKeyRotationDays = onionKeyRotationDays,
            heartbeatPeriodSec = heartbeatPeriodSec,
            sandbox = sandbox,
            disableNetwork = disableNetwork,
            nickname = nickname,
            contactInfo = contactInfo,
            bandwidthRateBytes = bandwidthRateBytes,
            bandwidthBurstBytes = bandwidthBurstBytes,
            circuitBuildTimeoutSec = circuitBuildTimeoutSec,
            maxClientCircuitsPending = maxClientCircuitsPending,
            connLimit = connLimit,
            keepalivePeriodSec = keepalivePeriodSec,
            fetchDirInfoEarly = fetchDirInfoEarly,
            avoidDiskWrites = avoidDiskWrites,
            disableDebuggerAttachment = disableDebuggerAttachment,
            useEntryGuards = useEntryGuards,
            numEntryGuards = numEntryGuards,
            entryNodes = entryNodes.toList(),
            strictNodes = strictNodes,
            httpTunnelPort = httpTunnelPort,
            longLivedPorts = longLivedPorts ?: TorConfig.DEFAULT_LONG_LIVED_PORTS,
            mapAddress = mapAddress.toList(),
            accountingMaxBytes = accountingMaxBytes,
            accountingIntervalSec = accountingIntervalSec,
            pathBias = pathBiasOpts.copy(dropGuards = pathBiasDropGuards || pathBiasOpts.dropGuards),
            pathBiasDropGuards = pathBiasDropGuards || pathBiasOpts.dropGuards,
            geoIpFile = geoIpFile,
            automapHostsOnResolve = automapHostsOnResolve,
            automapHostsSuffixes = automapHostsSuffixes,
            virtualAddrNetworkIpv4 = virtualAddrNetworkIpv4,
            maxOnionQueueDelayMs = maxOnionQueueDelayMs,
            circuitPriorityHalflifeMsec = circuitPriorityHalflifeMsec,
            dosOptions = dosOpts,
            newCircuitPeriodSec = newCircuitPeriodSec,
            learnCircuitBuildTimeout = learnCircuitBuildTimeout,
            schedulers = schedulers,
            authoritativeDirectory = authoritativeDirectory,
            v3AuthoritativeDirectory = v3AuthoritativeDirectory,
            testingTorNetwork = testingTorNetwork,
            useMicrodescriptors = useMicrodescriptors,
            fetchUselessDescriptors = fetchUselessDescriptors,
            downloadExtraInfo = downloadExtraInfo,
            assumeReachable = assumeReachable,
            bridgeRelay = bridgeRelay,
            extendAllowPrivateAddresses = extendAllowPrivateAddresses,
            dirAllowPrivateAddresses = dirAllowPrivateAddresses,
            refuseUnknownExits = refuseUnknownExits,
            fetchDirInfoExtraEarly = fetchDirInfoExtraEarly,
            runtime = runtimeOpts,
            acknowledgedKeys = acknowledged,
            unrecognizedKeys = unrecognized,
        )
    }
}
