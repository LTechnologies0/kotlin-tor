package org.kotlintor.config

/**
 * Keys named in torrc(5) / C Tor options that kotlin-tor accepts at parse time.
 * Typed fields in [TorConfig] win when present; otherwise values land in
 * [TorConfig.acknowledgedKeys] for GETCONF / SAVECONF parity.
 */
object TorrcManpageKeys {
    val ALL: Set<String> = setOf(
        // Files / process
        "DataDirectory", "CacheDirectory", "KeyDirectory", "PidFile", "RunAsDaemon", "User",
        "Log", "LogMessageDomains", "SafeLogging", "SyslogIdentityTag", "AndroidIdentityTag",
        "Sandbox", "NoExec", "KeepBindCapabilities", "DisableDebuggerAttachment", "DisableAllSwap",
        "HardwareAccel", "AccelName", "AccelDir", "AvoidDiskWrites", "CountPrivateBandwidth",
        // Client ports
        "SocksPort", "SocksPolicy", "SocksTimeout", "SafeSocks", "TestSocks", "WarnUnsafeSocks",
        "HTTPTunnelPort", "TransPort", "TransProxyType", "NATDPort", "DNSPort", "DNSListenAddress",
        "UdpTorGatewayPort",
        "ControlPort", "ControlSocket", "ControlSocketsGroupWritable", "CookieAuthentication",
        "CookieAuthFile", "CookieAuthFileGroupReadable", "HashedControlPassword",
        "ControlPortWriteToFile", "ControlPortFileGroupReadable", "OwningControllerProcess",
        "OwningControllerFD",
        // Network / bootstrap
        "DisableNetwork", "ClientOnly", "FetchDirInfoEarly", "FetchDirInfoExtraEarly",
        "FetchUselessDescriptors", "DownloadExtraInfo", "UseMicrodescriptors",
        "DirAuthority", "FallbackDir", "UseDefaultFallbackDirs", "DirAuthorityFallbackRate",
        "MaxConsensusAgeForDiffs", "FetchHidServDescriptors", "FetchServerDescriptors",
        "FetchV2Networkstatus", "ProtocolWarnings",
        // Bridges / PT
        "UseBridges", "Bridge", "ClientTransportPlugin", "ServerTransportPlugin",
        "ServerTransportListenAddr", "ServerTransportOptions", "ExtORPort", "ExtORPortCookieAuthFile",
        "BridgeRelay", "BridgeDistribution", "UpdateBridgesFromAuthority",
        // Paths / circuits
        "CircuitBuildTimeout", "LearnCircuitBuildTimeout", "CircuitStreamTimeout",
        "CircuitIdleTimeout", "CircuitDirtyTimeout", "CircuitUnusedTimeout", "MaxCircuitDirtiness",
        "MaxClientCircuitsPending", "KeepalivePeriod", "NewCircuitPeriod", "MaxOnionQueueDelay",
        "CircuitPriorityHalflife", "CircuitPriorityHalflifeMsec",
        "PathBias*", // wildcard handled separately
        "UseEntryGuards", "NumEntryGuards", "NumPrimaryGuards", "NumDirectoryGuards",
        "GuardLifetime", "GuardsKeepDesc", "EntryNodes", "StrictNodes", "ExcludeNodes",
        "ExcludeExitNodes", "ExitNodes", "MiddleNodes", "NodeFamily", "MyFamily",
        "EnforceDistinctSubnets", "LongLivedPorts", "MapAddress", "AutomapHostsOnResolve",
        "AutomapHostsSuffixes", "VirtualAddrNetworkIPv4", "VirtualAddrNetworkIPv6",
        "AllowNonRFC953Hostnames", "ClientUseIPv4", "ClientUseIPv6",
        "ClientPreferIPv6ORPort", "ClientPreferIPv6DirPort", "ClientRejectInternalAddresses",
        "ClientDNSRejectInternalAddresses", "FascistFirewall", "FirewallPorts", "ReachableAddresses",
        "ReachableORAddresses", "ReachableDirAddresses", "ConstrainedSockets", "ConstrainedSockSize",
        "VanguardsLiteEnabled",
        "ExtendAllowPrivateAddresses", "DirAllowPrivateAddresses", "RefuseUnknownExits",
        // Isolation
        "IsolateClientAddr", "IsolateSOCKSAuth", "IsolateClientProtocol", "IsolateDestPort",
        "IsolateDestAddr", "KeepAliveIsolateSOCKSAuth", "SessionGroup",
        // Relay
        "ORPort", "Address", "OutboundBindAddress", "OutboundBindAddressOR", "OutboundBindAddressExit",
        "OutboundBindAddressPT", "DirPort", "DirPortFrontPage", "AssumeReachable",
        "AssumeReachableIPv6", "AuthoritativeDirectory", "V3AuthoritativeDirectory",
        "BridgeAuthoritativeDir", "PublishServerDescriptor", "PublishHidServDescriptors",
        "ShutdownWaitLength", "HeartbeatPeriod", "MainloopStats", "CellStatistics",
        "PaddingStatistics", "DirReqStatistics", "EntryStatistics", "ExitPortStatistics",
        "ConnDirectionStatistics", "HiddenServiceStatistics", "ExtraInfoStatistics",
        "OverloadStatistics", "ConnLimit", "MaxMemInQueues", "MaxAdvertisedBandwidth",
        "RelayBandwidthRate", "RelayBandwidthBurst", "PerConnBWRate", "PerConnBWBurst",
        "BandwidthRate", "BandwidthBurst", "AccountingMax", "AccountingStart", "AccountingRule",
        "ExitRelay", "ExitPolicy", "ExitPolicyRejectPrivate", "ExitPolicyRejectLocalInterfaces",
        "ReducedExitPolicy", "IPv6Exit",
        "Nickname", "ContactInfo", "BridgeRecordUsageByCountry", "ServerDNSResolvConfFile",
        "ServerDNSAllowBrokenConfig", "ServerDNSSearchDomains", "ServerDNSDetectHijacking",
        "ServerDNSTestAddresses", "ServerDNSAllowNonRFC953Hostnames", "ServerDNSRandomizeCase",
        "NumCPUs", "OfflineMasterKey", "SigningKeyLifetime", "OnionKeyLifetime", "OnionKeyGracePeriod",
        "DoSCircuitCreationEnabled", "DoSCircuitCreationMinConnections", "DoSCircuitCreationRate",
        "DoSCircuitCreationBurst", "DoSCircuitCreationDefenseType", "DoSCircuitCreationDefenseTimePeriod",
        "DoSConnectionEnabled", "DoSConnectionMaxConcurrentCount", "DoSConnectionDefenseType",
        "DoSRefuseSingleHopClientRendezvous", "DoSStreamCreationEnabled", "DoSStreamCreationRate",
        "DoSStreamCreationBurst", "DoSStreamCreationDefenseType",
        // HS
        "HiddenServiceDir", "HiddenServicePort", "HiddenServiceVersion", "HiddenServiceNonAnonymousMode",
        "HiddenServiceSingleHopMode", "HiddenServiceMaxStreams", "HiddenServiceMaxStreamsCloseCircuit",
        "HiddenServiceDirGroupReadable", "HiddenServiceNumIntroductionPoints",
        "HiddenServiceEnableIntroDoSDefense", "HiddenServiceEnableIntroDoSBurstPerSec",
        "HiddenServiceEnableIntroDoSRatePerSec", "HiddenServicePoWDefensesEnabled",
        "HiddenServicePoWQueueRate", "HiddenServicePoWQueueBurst", "HiddenServiceExportCircuitID",
        "HiddenServiceOnionBalanceInstance",
        // Metrics / misc
        "MetricsPort", "MetricsPortPolicy", "Padding", "ReducedPadding", "CircuitPadding",
        "ReducedCircuitPadding", "ConnectionPadding", "ReducedConnectionPadding",
        // Outbound proxies / dormant / conflux / KIST / dirauth vote timing
        "HTTPProxy", "HTTPSProxy", "Socks4Proxy", "Socks5Proxy", "TCPProxy", "TCPProxyProtocol",
        "AllDirActionsPrivate", "AlwaysCongestionControl", "CircuitsAvailableTimeout",
        "ClientBootstrapConsensusAuthorityDownloadInitialDelay",
        "ClientBootstrapConsensusAuthorityOnlyDownloadInitialDelay",
        "ClientBootstrapConsensusFallbackDownloadInitialDelay",
        "ClientBootstrapConsensusMaxInProgressTries", "CompiledProofOfWorkHash",
        "ConfluxEnabled", "ConfluxClientUX", "DirCache", "DisableOOSCheck",
        "DisablePredictedCircuits", "DisableSignalHandlers",
        "DormantCanceledByStartup", "DormantClientTimeout", "DormantOnFirstStartup",
        "DormantTimeoutDisabledByIdleStreams", "DormantTimeoutEnabled",
        "ExtendByEd25519ID", "GeoIPExcludeUnknown", "KISTSchedRunInterval",
        "KISTSockBufSizeFactor", "LeaveStreamsUnattached", "ManualOnionKeyRotation",
        "MaxHSDirCacheBytes", "MaxUnparseableDescSizeToLog", "PathsNeededToBuildCircuits",
        "ReconfigDropsBridgeDescs", "ReevaluateExitPolicy", "ReloadTorrcOnSIGHUP",
        "RephistTrackTime", "SSLKeyLifetime", "SbwsExit", "TokenBucketRefillInterval",
        "TrackHostExitsExpire", "TruncateLogFile", "UnixSocksGroupWritable", "UseGuardFraction",
        "V3AuthVotingInterval", "V3AuthVoteDelay", "V3AuthDistDelay", "V3AuthNIntervalsValid",
        "V3AuthUseLegacyKey", "AllFamilyIdsExpected",
        "TestingAuthKeyLifetime", "TestingAuthKeySlop",
        "TestingBridgeBootstrapDownloadInitialDelay", "TestingBridgeDownloadInitialDelay",
        "TestingClientConsensusDownloadInitialDelay", "TestingClientDownloadInitialDelay",
        "TestingClientMaxIntervalWithoutRequest", "TestingDirConnectionMaxStall",
        "TestingEnableCellStatsEvent", "TestingEnableConnBwEvent",
        "TestingLinkCertLifetime", "TestingLinkKeySlop", "TestingMinTimeToReportBandwidth",
        "TestingServerConsensusDownloadInitialDelay", "TestingServerDownloadInitialDelay",
        "TestingSigningKeySlop", "TestingV3AuthInitialDistDelay", "TestingV3AuthInitialVoteDelay",
        "TestingV3AuthInitialVotingInterval", "TestingV3AuthVotingStartOffset",
        "Schedulers", "SchedulerWindowSize", "SchedulerBurstSize",
    ).flatMap { key ->
        if (key.endsWith("*")) {
            // expand a few PathBias* names used in torrc
            listOf(
                "PathBiasCircThreshold", "PathBiasNoticeRate", "PathBiasWarnRate", "PathBiasExtremeRate",
                "PathBiasNoticeCountPercentile", "PathBiasScaleThreshold", "PathBiasScaleUseThreshold",
                "PathBiasDropGuards", "PathBiasUseThreshold", "PathBiasNoticeUseRate",
                "PathBiasExtremeUseRate", "PathBiasUseRate",
            )
        } else {
            listOf(key)
        }
    }.toSet()

    fun isKnown(key: String): Boolean =
        ALL.any { it.equals(key, ignoreCase = true) }
}
