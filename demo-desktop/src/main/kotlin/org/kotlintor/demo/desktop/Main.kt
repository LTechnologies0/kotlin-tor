package org.kotlintor.demo.desktop

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.List
import androidx.compose.material.icons.outlined.AccountTree
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Public
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path as ComposePath
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.kotlintor.demo.DemoEngineStatus
import org.kotlintor.demo.DemoFeatureId
import org.kotlintor.demo.DemoFeatures
import org.kotlintor.demo.DemoLogBuffer
import org.kotlintor.demo.DemoProfiler
import org.kotlintor.demo.DemoSession
import org.kotlintor.demo.DemoSessionOptions
import org.kotlintor.demo.DesktopVpnSession
import org.kotlintor.demo.FeatureCatalog
import org.kotlintor.demo.ProfilerSnapshot
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.nio.file.Path
private val LightColors = lightColorScheme(
    primary = Color(0xFF3F4756),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFD7E0F0),
    onPrimaryContainer = Color(0xFF121C2B),
    secondary = Color(0xFF565E6B),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFDAE2F0),
    onSecondaryContainer = Color(0xFF131B27),
    error = Color(0xFFBA1A1A),
    onError = Color(0xFFFFFFFF),
    background = Color(0xFFFBF8FD),
    onBackground = Color(0xFF1B1B1F),
    surface = Color(0xFFFBF8FD),
    onSurface = Color(0xFF1B1B1F),
    surfaceVariant = Color(0xFFE2E2E9),
    onSurfaceVariant = Color(0xFF45464C),
    outline = Color(0xFF75777D),
    outlineVariant = Color(0xFFC5C6CD),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFBFC7D8),
    onPrimary = Color(0xFF293040),
    primaryContainer = Color(0xFF3F4756),
    onPrimaryContainer = Color(0xFFD7E0F0),
    secondary = Color(0xFFBEC6D4),
    onSecondary = Color(0xFF28303C),
    secondaryContainer = Color(0xFF3E4653),
    onSecondaryContainer = Color(0xFFDAE2F0),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    background = Color(0xFF131316),
    onBackground = Color(0xFFE3E2E6),
    surface = Color(0xFF131316),
    onSurface = Color(0xFFE3E2E6),
    surfaceVariant = Color(0xFF45464C),
    onSurfaceVariant = Color(0xFFC5C6CD),
    outline = Color(0xFF8F9097),
    outlineVariant = Color(0xFF45464C),
)

fun main(args: Array<String>) {
    @Suppress("UNUSED_PARAMETER")
    val _args = args
    DemoLogBuffer.install()
    DemoLogBuffer.append("app", "kotlin-tor-demo starting")
    val session = DemoSession()
    val vpnSession = DesktopVpnSession()
    val features = DemoFeatures(session)
    val profiler = DemoProfiler()
    application {
        Window(
            onCloseRequest = {
                profiler.stop()
                runBlocking {
                    vpnSession.stop()
                    session.stop()
                }
                exitApplication()
            },
            title = "kotlin-tor demo",
            state = rememberWindowState(width = 1100.dp, height = 720.dp),
        ) {
            val dark = isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (dark) DarkColors else LightColors) {
                Surface(Modifier.fillMaxSize()) {
                    DemoDesktopApp(session, vpnSession, features, profiler)
                }
            }
        }
    }
}

@Composable
private fun DemoDesktopApp(
    session: DemoSession,
    vpnSession: DesktopVpnSession,
    features: DemoFeatures,
    profiler: DemoProfiler,
) {
    val scope = rememberCoroutineScope()
    var selected by remember { mutableStateOf(DemoFeatureId.OVERVIEW) }
    var status by remember { mutableStateOf("Idle — start the router") }
    var portsText by remember { mutableStateOf("") }
    var running by remember { mutableStateOf(false) }
    var vpnRunning by remember { mutableStateOf(false) }
    var vpnBusy by remember { mutableStateOf(false) }
    var vpnStatus by remember { mutableStateOf(DesktopVpnSession.availabilityMessage() ?: "Idle — Linux full-tunnel") }
    var busy by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf(0f) }
    var indeterminate by remember { mutableStateOf(false) }
    var dnssec by remember { mutableStateOf(false) }
    var recursive by remember { mutableStateOf("1.1.1.1:53") }
    var hostname by remember { mutableStateOf("check.torproject.org") }
    var dnsResult by remember { mutableStateOf("") }
    var proxyResult by remember { mutableStateOf("") }
    var circuitsText by remember { mutableStateOf("") }
    var dormant by remember { mutableStateOf(false) }
    var onion by remember { mutableStateOf("") }
    var onionResult by remember { mutableStateOf("") }
    var controlResult by remember { mutableStateOf("") }
    var logs by remember { mutableStateOf(DemoLogBuffer.snapshot()) }
    var logsSubTab by remember { mutableStateOf(0) }
    var profilerLive by remember { mutableStateOf(true) }
    var profilerInterval by remember { mutableStateOf(1_000L) }
    var profilerSnap by remember { mutableStateOf(profiler.snapshot()) }

    DisposableEffect(Unit) {
        val logListener: (String) -> Unit = { logs = DemoLogBuffer.snapshot() }
        val profListener: (ProfilerSnapshot) -> Unit = { profilerSnap = it }
        DemoLogBuffer.addListener(logListener)
        profiler.addListener(profListener)
        onDispose {
            DemoLogBuffer.removeListener(logListener)
            profiler.removeListener(profListener)
            profiler.stop()
        }
    }

    LaunchedEffect(selected, logsSubTab, profilerLive, profilerInterval) {
        val want = selected == DemoFeatureId.LOGS && logsSubTab == 1 && profilerLive
        if (want) {
            profiler.setIntervalMs(profilerInterval)
            if (!profiler.isLive()) {
                profiler.start(sessionProvider = { session }, intervalMs = profilerInterval)
            } else {
                profiler.setIntervalMs(profilerInterval)
            }
            profilerSnap = profiler.snapshot()
        } else {
            profiler.stop()
            profilerSnap = profiler.snapshot()
        }
    }

    LaunchedEffect(running) {
        if (!running) return@LaunchedEffect
        while (isActive && session.isRunning) {
            val line = session.bootstrapLine()
            status = line
            DemoFeatures.parseBootstrapProgress(line)?.let {
                progress = it / 100f
                indeterminate = false
            }
            val p = session.ports()
            portsText = buildString {
                appendLine("SOCKS5H   127.0.0.1:${p.socks}")
                appendLine("HTTP CONNECT 127.0.0.1:${p.http}")
                appendLine("DNSPort   127.0.0.1:${p.dns}")
                appendLine("Control   127.0.0.1:${p.control}")
                if (session.dnssecValidate()) appendLine("DNSSEC    validate → ${session.dnssecRecursive()}")
            }
            delay(1_000)
        }
    }

    LaunchedEffect(vpnRunning) {
        if (!vpnRunning) return@LaunchedEffect
        while (isActive && vpnSession.isRunning) {
            vpnStatus = vpnSession.status
            delay(1_000)
        }
    }

    val linuxDesktop = org.kotlintor.os.LinuxTunDevice.isLinux()
    val navItems = FeatureCatalog.forPlatform(android = false, linuxDesktop = linuxDesktop)
    val iconFor: (DemoFeatureId) -> ImageVector = { id ->
        when (id) {
            DemoFeatureId.OVERVIEW -> Icons.Outlined.Home
            DemoFeatureId.PROXIES -> Icons.Outlined.Link
            DemoFeatureId.VPN -> Icons.Outlined.VpnKey
            DemoFeatureId.DNS -> Icons.Outlined.Dns
            DemoFeatureId.CIRCUITS -> Icons.Outlined.AccountTree
            DemoFeatureId.ONION -> Icons.Outlined.Public
            DemoFeatureId.CONTROL -> Icons.Outlined.Settings
            DemoFeatureId.LOGS -> Icons.AutoMirrored.Outlined.List
        }
    }

    Row(Modifier.fillMaxSize()) {
        NavigationRail {
            Text(
                "kotlin-tor",
                Modifier.padding(horizontal = 12.dp, vertical = 16.dp),
                style = MaterialTheme.typography.titleMedium,
            )
            navItems.forEach { feature ->
                NavigationRailItem(
                    selected = selected == feature.id,
                    onClick = { selected = feature.id },
                    icon = { Icon(iconFor(feature.id), contentDescription = feature.title) },
                    label = { Text(feature.title) },
                )
            }
        }
        VerticalDivider(Modifier.fillMaxHeight())
        Column(
            Modifier
                .weight(1f)
                .fillMaxHeight()
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            val feature = navItems.first { it.id == selected }
            Text(feature.title, style = MaterialTheme.typography.headlineSmall)
            Text(
                feature.description,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when (selected) {
                DemoFeatureId.OVERVIEW -> {
                    Text(
                        DemoEngineStatus.HONESTY_NOTE,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                            Text(status, fontFamily = FontFamily.Monospace)
                            if (indeterminate) LinearProgressIndicator(Modifier.fillMaxWidth())
                            else LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
                            Button(
                                onClick = {
                                    if (vpnRunning) {
                                        status = "Stop VPN first"
                                        return@Button
                                    }
                                    busy = true
                                    indeterminate = true
                                    status = "Starting…"
                                    scope.launch {
                                        runCatching {
                                            session.start(
                                                DemoSessionOptions(
                                                    dataDirectory = demoDataDir("router"),
                                                    dnssecValidate = dnssec,
                                                    dnssecRecursive = recursive.ifBlank { "1.1.1.1:53" },
                                                ),
                                            )
                                        }.onSuccess {
                                            running = true
                                            busy = false
                                            status = session.bootstrapLine()
                                        }.onFailure { t ->
                                            busy = false
                                            indeterminate = false
                                            running = false
                                            status = "Error: ${t.message}"
                                            DemoLogBuffer.append("error", t.stackTraceToString())
                                        }
                                    }
                                },
                                enabled = !running && !busy && !vpnRunning,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Start") }
                            TextButton(
                                onClick = {
                                    scope.launch {
                                        session.stop()
                                        running = false
                                        portsText = ""
                                        progress = 0f
                                        indeterminate = false
                                        status = "Idle — start the router"
                                    }
                                },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Stop") }
                        }
                    }
                    Text("Bound ports", style = MaterialTheme.typography.labelLarge)
                    OutputBlock(portsText.ifBlank { "—" })
                }

                DemoFeatureId.PROXIES -> {
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    scope.launch {
                                        proxyResult = features.socksSelfCheck()
                                        DemoLogBuffer.append("check", proxyResult)
                                    }
                                },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Check Tor (SOCKS)") }
                            OutlinedButton(
                                onClick = { scope.launch { features.newnym() } },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("NEWNYM") }
                            OutputBlock(proxyResult)
                        }
                    }
                }

                DemoFeatureId.VPN -> {
                    val blocked = DesktopVpnSession.availabilityMessage()
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                "Linux full-tunnel: TUN → OnionTunnel → Tor. " +
                                    "Only Tor OR/PT uplink sockets escape via SO_MARK (not LAN excludes). " +
                                    "Requires CAP_NET_ADMIN.",
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                style = MaterialTheme.typography.bodySmall,
                            )
                            if (blocked != null) {
                                Text(blocked, color = MaterialTheme.colorScheme.error)
                            } else {
                                Text(vpnStatus, fontFamily = FontFamily.Monospace)
                                Button(
                                    onClick = {
                                        if (running) {
                                            vpnStatus = "Stop the loopback router first"
                                            return@Button
                                        }
                                        vpnBusy = true
                                        vpnStatus = "Starting VPN…"
                                        scope.launch {
                                            runCatching {
                                                vpnSession.start(demoDataDir("vpn"))
                                            }.onSuccess {
                                                vpnRunning = true
                                                vpnBusy = false
                                                vpnStatus = vpnSession.status
                                            }.onFailure { t ->
                                                vpnBusy = false
                                                vpnRunning = false
                                                vpnStatus = "VPN error: ${t.message}"
                                                DemoLogBuffer.append("vpn", t.stackTraceToString())
                                            }
                                        }
                                    },
                                    enabled = !vpnRunning && !vpnBusy && !running,
                                    modifier = Modifier.fillMaxWidth(),
                                ) { Text("Start VPN") }
                                TextButton(
                                    onClick = {
                                        scope.launch {
                                            vpnSession.stop()
                                            vpnRunning = false
                                            vpnStatus = "Idle — Linux full-tunnel"
                                        }
                                    },
                                    enabled = vpnRunning,
                                    modifier = Modifier.fillMaxWidth(),
                                ) { Text("Stop VPN") }
                            }
                        }
                    }
                }

                DemoFeatureId.DNS -> {
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = hostname,
                                onValueChange = { hostname = it },
                                label = { Text("Hostname") },
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Button(
                                onClick = {
                                    scope.launch {
                                        dnsResult = features.resolve(hostname)
                                        DemoLogBuffer.append("dns", dnsResult)
                                    }
                                },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Resolve") }
                            OutputBlock(dnsResult)
                        }
                    }
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = dnssec, onCheckedChange = { dnssec = it }, enabled = !running)
                                Text("DNSSEC validate (applies on next Start)")
                            }
                            OutlinedTextField(
                                value = recursive,
                                onValueChange = { recursive = it },
                                label = { Text("DNSSEC recursive host:port") },
                                enabled = !running,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    }
                }

                DemoFeatureId.CIRCUITS -> {
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    val circ = features.circuitStatusLines().joinToString("\n").ifBlank { "(no circuits)" }
                                    val guards = features.guardStatusLines().joinToString("\n").ifBlank { "(no guards)" }
                                    circuitsText = "CIRC\n$circ\n\nGUARD\n$guards"
                                },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Refresh") }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = dormant,
                                    onCheckedChange = {
                                        dormant = it
                                        runCatching { features.setDormant(it) }
                                    },
                                    enabled = running,
                                )
                                Text("Dormant")
                            }
                            OutputBlock(circuitsText)
                        }
                    }
                }

                DemoFeatureId.ONION -> {
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedTextField(
                                value = onion,
                                onValueChange = { onion = it },
                                label = { Text("v3 onion address") },
                                modifier = Modifier.fillMaxWidth(),
                            )
                            Button(
                                onClick = {
                                    scope.launch {
                                        onionResult = features.fetchOnionDescriptor(onion)
                                        DemoLogBuffer.append("hs", onionResult.lines().firstOrNull() ?: onionResult)
                                    }
                                },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("Fetch descriptor") }
                            OutputBlock(onionResult)
                        }
                    }
                }

                DemoFeatureId.CONTROL -> {
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = {
                                    scope.launch {
                                        controlResult = features.controlGetInfo()
                                        DemoLogBuffer.append("control", controlResult.lines().firstOrNull() ?: controlResult)
                                    }
                                },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("GETINFO") }
                            OutlinedButton(
                                onClick = {
                                    scope.launch {
                                        controlResult = features.controlSignal("NEWNYM")
                                        DemoLogBuffer.append("control", controlResult)
                                    }
                                },
                                enabled = running,
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text("SIGNAL NEWNYM") }
                            OutputBlock(controlResult)
                        }
                    }
                }

                DemoFeatureId.LOGS -> {
                    TabRow(selectedTabIndex = logsSubTab) {
                        Tab(selected = logsSubTab == 0, onClick = { logsSubTab = 0 }, text = { Text("Logs") })
                        Tab(selected = logsSubTab == 1, onClick = { logsSubTab = 1 }, text = { Text("Profiler") })
                    }
                    if (logsSubTab == 0) {
                        Row {
                            TextButton(onClick = {
                                DemoLogBuffer.clear()
                                logs = DemoLogBuffer.snapshot()
                            }) { Text("Clear") }
                        }
                        OutputBlock(logs.ifBlank { "No log lines yet." })
                    } else {
                        ProfilerPanel(
                            snap = profilerSnap,
                            live = profilerLive,
                            intervalMs = profilerInterval,
                            onLiveChange = { profilerLive = it },
                            onIntervalChange = { profilerInterval = it },
                            onResetPeaks = { profiler.resetPeaks() },
                            onCopy = {
                                val text = profiler.formatReport(profilerSnap)
                                Toolkit.getDefaultToolkit().systemClipboard
                                    .setContents(StringSelection(text), null)
                            },
                            report = profiler.formatReport(profilerSnap),
                        )
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun OutputBlock(text: String) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.45f),
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text,
            Modifier.padding(12.dp),
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ProfilerPanel(
    snap: ProfilerSnapshot,
    live: Boolean,
    intervalMs: Long,
    onLiveChange: (Boolean) -> Unit,
    onIntervalChange: (Long) -> Unit,
    onResetPeaks: () -> Unit,
    onCopy: () -> Unit,
    report: String,
) {
    val s = snap.latest
    Text(
        "Process heap, threads, GC, CPU, and Tor session counters.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                Text("Live sampling")
                Switch(checked = live, onCheckedChange = onLiveChange)
            }
            Text("Sample interval", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(250L to "250 ms", 1_000L to "1 s", 2_000L to "2 s", 5_000L to "5 s").forEach { (ms, label) ->
                    FilterChip(
                        selected = intervalMs == ms,
                        onClick = { onIntervalChange(ms) },
                        label = { Text(label) },
                    )
                }
            }
            Row {
                OutlinedButton(onClick = onResetPeaks) { Text("Reset peaks") }
                TextButton(onClick = onCopy) { Text("Copy report") }
            }
            Text(
                buildString {
                    append("samples=${snap.sampleCount}  interval=${snap.intervalMs}ms  ")
                    append(if (snap.live) "LIVE" else "paused")
                    if (s != null) {
                        append("  cost=${"%.2f".format(s.sampleCostNs / 1_000_000.0)}ms")
                        append("  up=${DemoProfiler.formatDuration(s.jvmUptimeMs)}")
                    }
                },
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Heap", style = MaterialTheme.typography.titleMedium)
            if (s == null) {
                Text("Start sampling to collect metrics.")
            } else {
                Text(
                    "${DemoProfiler.formatBytes(s.heapUsedBytes)} / ${DemoProfiler.formatBytes(s.heapMaxBytes)}  (${"%.1f".format(DemoProfiler.heapRatio(s) * 100)}%)",
                    fontFamily = FontFamily.Monospace,
                )
                LinearProgressIndicator(
                    progress = { DemoProfiler.heapRatio(s).toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
                Sparkline(snap.history.map { it.heapUsedBytes.toDouble() })
                OutputBlock(
                    buildString {
                        appendLine("committed ${DemoProfiler.formatBytes(s.heapCommittedBytes)}")
                        appendLine("Δ ${DemoProfiler.formatRate(snap.heapDeltaBytesPerSec)}/s")
                        appendLine("peak ${DemoProfiler.formatBytes(snap.peaks.heapUsedBytes)}")
                        s.nonHeapUsedBytes?.let { appendLine("non-heap ${DemoProfiler.formatBytes(it)}") }
                    }.trimEnd(),
                )
            }
        }
    }

    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Threads & uptime", style = MaterialTheme.typography.titleMedium)
            if (s != null) {
                OutputBlock(
                    buildString {
                        appendLine("threads ${s.threadCount}  daemon ${s.daemonThreadCount}")
                        appendLine("peak ${s.peakThreadCount} (session ${snap.peaks.threadCount})")
                        appendLine("cpus ${s.availableProcessors}")
                        appendLine("uptime ${DemoProfiler.formatDuration(s.jvmUptimeMs)}")
                    }.trimEnd(),
                )
                Text("Process CPU", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
                LinearProgressIndicator(
                    progress = { (s.processCpuLoad ?: 0.0).toFloat().coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }

    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Garbage collection", style = MaterialTheme.typography.titleMedium)
            if (s != null) {
                OutputBlock(
                    buildString {
                        appendLine("collections ${s.gcCollectionCount}")
                        appendLine("time ${s.gcTimeMs} ms")
                        appendLine("Δ ${"%.2f".format(snap.gcDeltaMsPerSec)} ms/s")
                        appendLine("CPU process ${DemoProfiler.formatCpu(s.processCpuLoad)}  system ${DemoProfiler.formatCpu(s.systemCpuLoad)}")
                        appendLine("CPU peak ${DemoProfiler.formatCpu(snap.peaks.processCpuLoad)}")
                    }.trimEnd(),
                )
            }
        }
    }

    OutlinedCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Tor session", style = MaterialTheme.typography.titleMedium)
            Sparkline(snap.history.map { (it.torBytesRead + it.torBytesWritten).toDouble() })
            OutputBlock(
                if (s?.torRunning == true) {
                    buildString {
                        appendLine("circuits ${s.torCircuitCount}")
                        appendLine("read ${DemoProfiler.formatBytes(s.torBytesRead)}  (${DemoProfiler.formatRate(snap.readBytesPerSec)}/s)")
                        appendLine("written ${DemoProfiler.formatBytes(s.torBytesWritten)}  (${DemoProfiler.formatRate(snap.writeBytesPerSec)}/s)")
                        appendLine("bootstrap ${s.torBootstrapProgress ?: "?"}  ${s.torBootstrapLine.orEmpty()}")
                        appendLine("read peak ${DemoProfiler.formatBytes(snap.peaks.torBytesRead)}")
                        appendLine("write peak ${DemoProfiler.formatBytes(snap.peaks.torBytesWritten)}")
                    }.trimEnd()
                } else {
                    "session not running"
                },
            )
        }
    }

    Text("Full report", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
    OutputBlock(report.ifBlank { "Start sampling to collect metrics." })
}

@Composable
private fun Sparkline(values: List<Double>, modifier: Modifier = Modifier) {
    val primary = MaterialTheme.colorScheme.primary
    val outline = MaterialTheme.colorScheme.outlineVariant
    Canvas(modifier.fillMaxWidth().height(56.dp)) {
        val pad = 4.dp.toPx()
        drawLine(outline, Offset(pad, size.height / 2f), Offset(size.width - pad, size.height / 2f), strokeWidth = 1f)
        if (values.size < 2) return@Canvas
        val min = values.minOrNull() ?: 0.0
        val max = values.maxOrNull() ?: 1.0
        val span = (max - min).coerceAtLeast(1e-3)
        val usableW = size.width - pad * 2
        val usableH = size.height - pad * 2
        val path = ComposePath()
        val fill = ComposePath()
        values.forEachIndexed { i, v ->
            val x = pad + usableW * i / (values.size - 1).coerceAtLeast(1)
            val y = pad + usableH * (1f - ((v - min) / span).toFloat())
            if (i == 0) {
                path.moveTo(x, y)
                fill.moveTo(x, size.height - pad)
                fill.lineTo(x, y)
            } else {
                path.lineTo(x, y)
                fill.lineTo(x, y)
            }
        }
        fill.lineTo(pad + usableW, size.height - pad)
        fill.close()
        drawPath(fill, primary.copy(alpha = 0.2f))
        drawPath(path, primary, style = Stroke(width = 2f))
    }
}

/** Tor state under ~/.cache (or $KOTLIN_TOR_DEMO_DATA) — not inside the packaged app tree. */
private fun demoDataDir(name: String): Path {
    val override = System.getenv("KOTLIN_TOR_DEMO_DATA")?.takeIf { it.isNotBlank() }
    val root = if (override != null) {
        Path.of(override)
    } else {
        Path.of(System.getProperty("user.home"), ".cache", "kotlin-tor-demo")
    }
    return root.resolve(name)
}
