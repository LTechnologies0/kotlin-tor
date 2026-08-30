package org.kotlintor.os

/**
 * Linux route / policy-routing helpers for full-tunnel VPN.
 *
 * Sequence:
 * 1. [snapshotPhysicalDefault] before changing routes
 * 2. [installProtectTable] — marked packets (Tor uplink) keep physical default
 * 3. Create TUN + [configureTunAddress]
 * 4. [installDefaultViaTun]
 * 5. On stop: [teardown] restores prior state
 *
 * Uses the `ip` CLI (iproute2) — same operational surface as system VPN scripts;
 * fail-closed if commands fail.
 */
class LinuxTunRoutes(
    private val fwmark: Int = LinuxSocketMarkProtector.DEFAULT_FWMARK,
    private val tableId: Int = PROTECT_TABLE,
) {
    data class PhysicalDefault(
        val gateway: String?,
        val device: String?,
        val rawLine: String,
    )

    private var physical: PhysicalDefault? = null
    private var tunName: String? = null
    private var protectInstalled = false
    private var defaultViaTun = false
    private val undo = ArrayDeque<List<String>>()

    fun snapshotPhysicalDefault(): PhysicalDefault {
        val out = runIpCapture("route", "show", "default")
        val line = out.lines().firstOrNull { it.startsWith("default") }
            ?: error("No physical default route — cannot install full-tunnel safely")
        val gw = Regex("""via\s+(\S+)""").find(line)?.groupValues?.get(1)
        val dev = Regex("""dev\s+(\S+)""").find(line)?.groupValues?.get(1)
        val snap = PhysicalDefault(gw, dev, line.trim())
        physical = snap
        return snap
    }

    /**
     * Table [tableId]: default via physical GW; rule: fwmark → that table.
     * Must run before Tor OR dials and before replacing the main default route.
     */
    fun installProtectTable(snap: PhysicalDefault = physical ?: snapshotPhysicalDefault()) {
        check(!protectInstalled) { "protect table already installed" }
        val gw = snap.gateway ?: error("Physical default has no gateway (via …)")
        val dev = snap.device ?: error("Physical default has no device (dev …)")
        runIp("route", "replace", "default", "via", gw, "dev", dev, "table", tableId.toString())
        undo.addFirst(listOf("route", "flush", "table", tableId.toString()))
        runIp("rule", "add", "fwmark", fwmark.toString(), "table", tableId.toString(), "priority", "100")
        undo.addFirst(listOf("rule", "del", "fwmark", fwmark.toString(), "table", tableId.toString()))
        protectInstalled = true
    }

    fun configureTunAddress(
        tunName: String,
        localCidr: String = TUN_LOCAL_CIDR,
        peer: String = TUN_PEER,
    ) {
        this.tunName = tunName
        runIp("link", "set", "dev", tunName, "up")
        runIp("addr", "replace", localCidr, "peer", peer, "dev", tunName)
        undo.addFirst(listOf("addr", "flush", "dev", tunName))
    }

    fun installDefaultViaTun(
        tunName: String = this.tunName ?: error("TUN not configured"),
        peer: String = TUN_PEER,
    ) {
        check(protectInstalled) { "Install protect table before default-via-TUN" }
        runIp("route", "replace", "default", "via", peer, "dev", tunName)
        defaultViaTun = true
        // Restore physical default on undo (best-effort from snapshot)
        val snap = physical
        if (snap != null && snap.gateway != null && snap.device != null) {
            undo.addFirst(
                listOf("route", "replace", "default", "via", snap.gateway, "dev", snap.device),
            )
        }
    }

    fun teardown() {
        while (undo.isNotEmpty()) {
            val cmd = undo.removeFirst()
            runCatching { runIp(*cmd.toTypedArray()) }
        }
        // Extra best-effort cleanup
        tunName?.let { name ->
            runCatching { runIp("link", "set", "dev", name, "down") }
        }
        protectInstalled = false
        defaultViaTun = false
        tunName = null
    }

    companion object {
        const val PROTECT_TABLE: Int = 100
        /** Point-to-point style addresses inside the tunnel. */
        const val TUN_LOCAL_CIDR: String = "10.87.0.2/32"
        const val TUN_PEER: String = "10.87.0.1"
        const val TUN_DNS: String = "10.87.0.1"

        fun runIp(vararg args: String) {
            val pb = ProcessBuilder(listOf("ip") + args.toList())
            pb.redirectErrorStream(true)
            val proc = pb.start()
            val out = proc.inputStream.bufferedReader().readText()
            val ok = proc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS) && proc.exitValue() == 0
            if (!ok) {
                error("ip ${args.joinToString(" ")} failed: ${out.trim()}")
            }
        }

        fun runIpCapture(vararg args: String): String {
            val pb = ProcessBuilder(listOf("ip") + args.toList())
            pb.redirectErrorStream(true)
            val proc = pb.start()
            val out = proc.inputStream.bufferedReader().readText()
            val ok = proc.waitFor(10, java.util.concurrent.TimeUnit.SECONDS) && proc.exitValue() == 0
            if (!ok) error("ip ${args.joinToString(" ")} failed: ${out.trim()}")
            return out
        }

        fun hasIpBinary(): Boolean =
            runCatching {
                val pb = ProcessBuilder("ip", "-V")
                pb.redirectErrorStream(true)
                val p = pb.start()
                p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) && p.exitValue() == 0
            }.getOrDefault(false)
    }
}
