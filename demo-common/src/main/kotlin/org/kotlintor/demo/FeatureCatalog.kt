package org.kotlintor.demo

/**
 * Demo surfaces shared by Android / Desktop shells.
 */
enum class DemoFeatureId {
    OVERVIEW,
    PROXIES,
    VPN,
    DNS,
    CIRCUITS,
    ONION,
    CONTROL,
    LOGS,
}

enum class Availability {
    ALL,
    /** Android VpnService path. */
    ANDROID_ONLY,
    /** Linux desktop full-tunnel (SO_MARK + TUN). */
    LINUX_DESKTOP,
    /** Shown on Android and Linux desktop; stubbed elsewhere. */
    MOBILE_OR_LINUX,
}

data class DemoFeature(
    val id: DemoFeatureId,
    val title: String,
    val description: String,
    val availability: Availability = Availability.ALL,
)

object FeatureCatalog {
    val features: List<DemoFeature> = listOf(
        DemoFeature(
            DemoFeatureId.OVERVIEW,
            "Overview",
            "Bootstrap Tor, watch progress, see bound ports. ${DemoEngineStatus.L1_SNAPSHOT}",
        ),
        DemoFeature(
            DemoFeatureId.PROXIES,
            "Proxies",
            "SOCKS5H and HTTP CONNECT on loopback; NEWNYM; Tor check.",
        ),
        DemoFeature(
            DemoFeatureId.VPN,
            "VPN / TUN",
            "Full-tunnel: Android VpnService or Linux TUN + OnionTunnel (Tor uplink excluded).",
            Availability.MOBILE_OR_LINUX,
        ),
        DemoFeature(
            DemoFeatureId.DNS,
            "DNS / DNSSEC",
            "Resolve via Tor with per-request circuit isolation; optional DNSSEC.",
        ),
        DemoFeature(
            DemoFeatureId.CIRCUITS,
            "Circuits",
            "Circuit and guard status; dormant mode; path build uses ntor-v3 / CC when available.",
        ),
        DemoFeature(
            DemoFeatureId.ONION,
            "Onion",
            "Fetch a v3 onion service descriptor via HSDirs (hs_client / hs_descriptor path).",
        ),
        DemoFeature(
            DemoFeatureId.CONTROL,
            "Control",
            "Cookie AUTHENTICATE, GETINFO, SIGNAL NEWNYM (control-spec subset).",
        ),
        DemoFeature(
            DemoFeatureId.LOGS,
            "Logs",
            "Live engine logs and a process/Tor profiler.",
        ),
    )

    fun forPlatform(android: Boolean, linuxDesktop: Boolean = false): List<DemoFeature> =
        features.filter { f ->
            when (f.availability) {
                Availability.ALL -> true
                Availability.ANDROID_ONLY -> android
                Availability.LINUX_DESKTOP -> linuxDesktop
                Availability.MOBILE_OR_LINUX -> android || linuxDesktop
            }
        }
}
