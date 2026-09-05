package org.kotlintor.demo.android

import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.ActionBarDrawerToggle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.getSystemService
import androidx.core.view.GravityCompat
import androidx.drawerlayout.widget.DrawerLayout
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kotlintor.android.KotlinTorVpnService
import org.kotlintor.demo.DemoFeatures
import org.kotlintor.demo.DemoLogBuffer
import org.kotlintor.demo.DemoProfiler
import org.kotlintor.demo.DemoSession
import org.kotlintor.demo.DemoSessionOptions
import org.kotlintor.demo.ProfilerSnapshot
import org.kotlintor.demo.android.databinding.ActivityDemoBinding
import java.net.Proxy
import java.nio.file.Path

/**
 * Clean Material 3 Android shell over [DemoSession] / [DemoFeatures].
 * VPN remains Android-only via [DemoVpnService].
 */
class DemoActivity : AppCompatActivity() {
    private lateinit var binding: ActivityDemoBinding
    private val session = DemoSession()
    private val features = DemoFeatures(session)
    private val profiler = DemoProfiler()
    private var pollJob: Job? = null
    private var mode: Mode = Mode.IDLE
    private var vpnSocksPort: Int = -1
    private var autoScrollLogs = true
    private var useRail = false
    private var logsTabProfiler = false
    private var profilerWantLive = true

    private enum class Mode { IDLE, ROUTER, VPN }

    private val panels by lazy {
        listOf(
            binding.panelHome.root,
            binding.panelProxies.root,
            binding.panelVpn.root,
            binding.panelDns.root,
            binding.panelCircuits.root,
            binding.panelOnion.root,
            binding.panelControl.root,
            binding.panelLogs.root,
        )
    }

    private val logListener: (String) -> Unit = {
        runOnUiThread { refreshLogsView(scrollToEnd = autoScrollLogs) }
    }

    private val profilerListener: (ProfilerSnapshot) -> Unit = { snap ->
        runOnUiThread { renderProfiler(snap) }
    }

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            setStatus("VPN consent denied")
            binding.panelVpn.btnVpnStart.isEnabled = true
        }
    }

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != KotlinTorVpnService.ACTION_STATUS) return
            val state = intent.getStringExtra(KotlinTorVpnService.EXTRA_STATE).orEmpty()
            val message = intent.getStringExtra(KotlinTorVpnService.EXTRA_MESSAGE).orEmpty()
            vpnSocksPort = intent.getIntExtra(KotlinTorVpnService.EXTRA_SOCKS_PORT, -1)
            when (state) {
                KotlinTorVpnService.STATUS_BOOTSTRAPPING -> {
                    mode = Mode.VPN
                    setStatus(message.ifBlank { "VPN bootstrapping…" })
                    setVpnUi(running = true, ready = false)
                    updateModeChips()
                }
                KotlinTorVpnService.STATUS_READY -> {
                    mode = Mode.VPN
                    setStatus("VPN ready — $message")
                    binding.panelVpn.vpnStatusDetail.text = buildString {
                        appendLine("Mode: VpnService + OnionTunnel")
                        appendLine("TUN DNS  ${org.kotlintor.net.stack.FakeIpDnsCookies.FAKE_RESOLVER_V4}")
                        if (vpnSocksPort > 0) appendLine("SOCKS5H  127.0.0.1:$vpnSocksPort")
                    }
                    setVpnUi(running = true, ready = true)
                    updateModeChips()
                }
                KotlinTorVpnService.STATUS_ERROR -> {
                    setStatus("VPN error: $message")
                    mode = Mode.IDLE
                    setVpnUi(running = false, ready = false)
                    updateModeChips()
                }
                KotlinTorVpnService.STATUS_STOPPED -> {
                    if (mode == Mode.VPN) {
                        setStatus(getString(R.string.status_idle))
                        binding.panelHome.ports.text = ""
                        binding.panelVpn.vpnStatusDetail.text = ""
                        mode = Mode.IDLE
                    }
                    setVpnUi(running = false, ready = false)
                    updateModeChips()
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DemoLogBuffer.install()
        binding = ActivityDemoBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        applyAdaptiveNav()
        wireNavigation()
        wireHome()
        wireProxies()
        wireVpn()
        wireDns()
        wireCircuits()
        wireOnion()
        wireControl()
        wireLogs()

        setRouterUi(false)
        setVpnUi(running = false, ready = false)
        updateModeChips()
        refreshLogsView(scrollToEnd = true)
        showPanel(R.id.nav_home)
    }

    private fun applyAdaptiveNav() {
        useRail = resources.configuration.screenWidthDp >= 600
        if (useRail) {
            binding.navRail.visibility = View.VISIBLE
            binding.drawerLayout.setDrawerLockMode(DrawerLayout.LOCK_MODE_LOCKED_CLOSED)
            binding.toolbar.navigationIcon = null
        } else {
            binding.navRail.visibility = View.GONE
            binding.drawerLayout.setDrawerLockMode(DrawerLayout.LOCK_MODE_UNLOCKED)
            val toggle = ActionBarDrawerToggle(
                this,
                binding.drawerLayout,
                binding.toolbar,
                R.string.open_drawer,
                R.string.open_drawer,
            )
            binding.drawerLayout.addDrawerListener(toggle)
            toggle.syncState()
        }
    }

    private fun wireNavigation() {
        val select: (Int) -> Boolean = { itemId ->
            showPanel(itemId)
            if (!useRail) binding.drawerLayout.closeDrawer(GravityCompat.START)
            true
        }
        binding.navView.setCheckedItem(R.id.nav_home)
        binding.navView.setNavigationItemSelectedListener { select(it.itemId) }
        binding.navRail.setCheckedItem(R.id.nav_home)
        binding.navRail.setNavigationItemSelectedListener { select(it.itemId) }
    }

    private fun showPanel(navId: Int) {
        panels.forEach { it.visibility = View.GONE }
        val title = when (navId) {
            R.id.nav_proxies -> {
                binding.panelProxies.root.visibility = View.VISIBLE
                getString(R.string.nav_proxies)
            }
            R.id.nav_vpn -> {
                binding.panelVpn.root.visibility = View.VISIBLE
                getString(R.string.nav_vpn)
            }
            R.id.nav_dns -> {
                binding.panelDns.root.visibility = View.VISIBLE
                getString(R.string.nav_dns)
            }
            R.id.nav_circuits -> {
                binding.panelCircuits.root.visibility = View.VISIBLE
                getString(R.string.nav_circuits)
            }
            R.id.nav_onion -> {
                binding.panelOnion.root.visibility = View.VISIBLE
                getString(R.string.nav_onion)
            }
            R.id.nav_control -> {
                binding.panelControl.root.visibility = View.VISIBLE
                getString(R.string.nav_control)
            }
            R.id.nav_logs -> {
                binding.panelLogs.root.visibility = View.VISIBLE
                autoScrollLogs = true
                refreshLogsView(scrollToEnd = true)
                syncProfilerSampling()
                getString(R.string.nav_logs)
            }
            else -> {
                binding.panelHome.root.visibility = View.VISIBLE
                stopProfilerSampling()
                getString(R.string.nav_home)
            }
        }
        if (navId != R.id.nav_logs) stopProfilerSampling()
        binding.toolbar.title = title
        binding.navView.setCheckedItem(navId)
        if (useRail) binding.navRail.setCheckedItem(navId)
    }

    private fun wireHome() {
        binding.panelHome.btnStart.setOnClickListener { startRouter() }
        binding.panelHome.btnStop.setOnClickListener { stopRouter() }
        binding.panelHome.chipIdle.isClickable = false
        binding.panelHome.chipRouter.isClickable = false
        binding.panelHome.chipVpn.isClickable = false
    }

    private fun wireProxies() {
        binding.panelProxies.btnNewnym.setOnClickListener {
            lifecycleScope.launch {
                runCatching { features.newnym() }
                    .onSuccess { Toast.makeText(this@DemoActivity, "NEWNYM signaled", Toast.LENGTH_SHORT).show() }
                    .onFailure { Toast.makeText(this@DemoActivity, it.message, Toast.LENGTH_SHORT).show() }
            }
        }
        binding.panelProxies.btnCopySocks.setOnClickListener {
            val port = session.ports().socks
            if (port > 0) copy("socks5h://127.0.0.1:$port")
        }
        binding.panelProxies.btnCopyHttp.setOnClickListener {
            val port = session.ports().http
            if (port > 0) copy("http://127.0.0.1:$port")
        }
        binding.panelProxies.btnSelfCheck.setOnClickListener { runSocksSelfCheck() }
    }

    private fun wireVpn() {
        binding.panelVpn.btnVpnStart.setOnClickListener { requestVpn() }
        binding.panelVpn.btnVpnStop.setOnClickListener { stopVpn() }
        binding.panelVpn.btnVpnSelfCheck.setOnClickListener { runVpnSelfCheck() }
    }

    private fun wireDns() {
        binding.panelDns.switchDnssec.setOnCheckedChangeListener { _, checked ->
            DemoLogBuffer.append("dns", "DNSSEC prefer=$checked (applies on next Start)")
        }
        binding.panelDns.btnDnsResolve.setOnClickListener { runDnsResolve() }
    }

    private fun wireCircuits() {
        binding.panelCircuits.btnCircuitsRefresh.setOnClickListener { refreshCircuitsPanel() }
        binding.panelCircuits.switchDormant.setOnCheckedChangeListener { _, checked ->
            runCatching { features.setDormant(checked) }
        }
    }

    private fun wireOnion() {
        binding.panelOnion.btnOnionFetch.setOnClickListener { runOnionFetch() }
    }

    private fun wireControl() {
        binding.panelControl.btnControlGetInfo.setOnClickListener { runControlGetInfo() }
        binding.panelControl.btnControlNewnym.setOnClickListener { runControlSignal() }
    }

    private fun wireLogs() {
        val tabs = binding.panelLogs.logsTabs
        tabs.removeAllTabs()
        tabs.addTab(tabs.newTab().setText(R.string.logs_tab_logs))
        tabs.addTab(tabs.newTab().setText(R.string.logs_tab_profiler))
        tabs.addOnTabSelectedListener(object : com.google.android.material.tabs.TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: com.google.android.material.tabs.TabLayout.Tab) {
                logsTabProfiler = tab.position == 1
                binding.panelLogs.logsPane.visibility = if (logsTabProfiler) View.GONE else View.VISIBLE
                binding.panelLogs.profilerPane.visibility = if (logsTabProfiler) View.VISIBLE else View.GONE
                if (logsTabProfiler) {
                    renderProfiler(profiler.snapshot())
                    syncProfilerSampling()
                } else {
                    stopProfilerSampling()
                }
            }

            override fun onTabUnselected(tab: com.google.android.material.tabs.TabLayout.Tab) = Unit
            override fun onTabReselected(tab: com.google.android.material.tabs.TabLayout.Tab) = Unit
        })

        binding.panelLogs.btnLogClear.setOnClickListener {
            DemoLogBuffer.clear()
            refreshLogsView(scrollToEnd = true)
        }
        binding.panelLogs.btnLogCopy.setOnClickListener {
            copy(DemoLogBuffer.snapshot().ifBlank { getString(R.string.logs_empty) })
        }
        binding.panelLogs.logsScroll.setOnScrollChangeListener { _, _, scrollY, _, oldScrollY ->
            val child = binding.panelLogs.logsScroll.getChildAt(0) ?: return@setOnScrollChangeListener
            val atBottom = scrollY + binding.panelLogs.logsScroll.height >= child.height - 24
            if (scrollY < oldScrollY) autoScrollLogs = false
            if (atBottom) autoScrollLogs = true
        }

        binding.panelLogs.switchProfilerLive.setOnCheckedChangeListener { _, checked ->
            profilerWantLive = checked
            syncProfilerSampling()
        }
        binding.panelLogs.btnProfilerResetPeaks.setOnClickListener { profiler.resetPeaks() }
        binding.panelLogs.btnProfilerCopy.setOnClickListener {
            copy(profiler.formatReport())
        }
        binding.panelLogs.profilerIntervalChips.setOnCheckedStateChangeListener { _, _ ->
            val ms = when {
                binding.panelLogs.chipInterval250.isChecked -> 250L
                binding.panelLogs.chipInterval2000.isChecked -> 2_000L
                binding.panelLogs.chipInterval5000.isChecked -> 5_000L
                else -> 1_000L
            }
            profiler.setIntervalMs(ms)
            if (profiler.isLive()) {
                stopProfilerSampling()
                syncProfilerSampling()
            }
        }
        profiler.addListener(profilerListener)
        renderProfiler(profiler.snapshot())
    }

    private fun syncProfilerSampling() {
        val shouldRun = logsTabProfiler && profilerWantLive &&
            binding.panelLogs.root.visibility == View.VISIBLE
        if (shouldRun) {
            if (!profiler.isLive()) {
                profiler.start(sessionProvider = { session }, intervalMs = profiler.intervalMs())
            }
        } else {
            stopProfilerSampling()
        }
    }

    private fun stopProfilerSampling() {
        if (profiler.isLive()) profiler.stop()
    }

    private fun renderProfiler(snap: ProfilerSnapshot) {
        val s = snap.latest
        binding.panelLogs.profilerMeta.text = buildString {
            append("samples=${snap.sampleCount}  interval=${snap.intervalMs}ms  ")
            append(if (snap.live) "LIVE" else "paused")
            if (s != null) {
                append("  cost=${"%.2f".format(s.sampleCostNs / 1_000_000.0)}ms")
                append("  up=${DemoProfiler.formatDuration(s.jvmUptimeMs)}")
            }
        }
        if (s == null) {
            binding.panelLogs.profilerHeapLabel.text = getString(R.string.profiler_idle)
            binding.panelLogs.profilerHeapBar.progress = 0
            binding.panelLogs.profilerCpuBar.progress = 0
            binding.panelLogs.profilerHeapDetail.text = ""
            binding.panelLogs.profilerRuntimeDetail.text = ""
            binding.panelLogs.profilerGcDetail.text = ""
            binding.panelLogs.profilerTorDetail.text = "session not running"
            binding.panelLogs.profilerReport.text = getString(R.string.profiler_idle)
            binding.panelLogs.profilerHeapSpark.setValues(emptyList())
            binding.panelLogs.profilerTorSpark.setValues(emptyList())
            return
        }
        val heapPct = (DemoProfiler.heapRatio(s) * 1000).toInt().coerceIn(0, 1000)
        binding.panelLogs.profilerHeapBar.progress = heapPct
        binding.panelLogs.profilerHeapLabel.text =
            "${DemoProfiler.formatBytes(s.heapUsedBytes)} / ${DemoProfiler.formatBytes(s.heapMaxBytes)}  (${"%.1f".format(DemoProfiler.heapRatio(s) * 100)}%)"
        binding.panelLogs.profilerHeapDetail.text = buildString {
            appendLine("committed ${DemoProfiler.formatBytes(s.heapCommittedBytes)}")
            appendLine("Δ ${DemoProfiler.formatRate(snap.heapDeltaBytesPerSec)}/s")
            appendLine("peak ${DemoProfiler.formatBytes(snap.peaks.heapUsedBytes)}")
            s.nonHeapUsedBytes?.let { appendLine("non-heap ${DemoProfiler.formatBytes(it)}") }
        }.trimEnd()
        binding.panelLogs.profilerHeapSpark.setValues(
            snap.history.map { it.heapUsedBytes.toDouble() },
        )

        binding.panelLogs.profilerRuntimeDetail.text = buildString {
            appendLine("threads ${s.threadCount}  daemon ${s.daemonThreadCount}")
            appendLine("peak ${s.peakThreadCount} (session ${snap.peaks.threadCount})")
            appendLine("cpus ${s.availableProcessors}")
            appendLine("uptime ${DemoProfiler.formatDuration(s.jvmUptimeMs)}")
        }.trimEnd()

        val cpu = s.processCpuLoad
        binding.panelLogs.profilerCpuBar.progress =
            if (cpu == null) 0 else (cpu * 1000).toInt().coerceIn(0, 1000)
        binding.panelLogs.profilerGcDetail.text = buildString {
            appendLine("collections ${s.gcCollectionCount}")
            appendLine("time ${s.gcTimeMs} ms")
            appendLine("Δ ${"%.2f".format(snap.gcDeltaMsPerSec)} ms/s")
            appendLine("CPU process ${DemoProfiler.formatCpu(s.processCpuLoad)}  system ${DemoProfiler.formatCpu(s.systemCpuLoad)}")
            appendLine("CPU peak ${DemoProfiler.formatCpu(snap.peaks.processCpuLoad)}")
        }.trimEnd()

        binding.panelLogs.profilerTorDetail.text = if (s.torRunning) {
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
        }
        binding.panelLogs.profilerTorSpark.setValues(
            snap.history.map { (it.torBytesRead + it.torBytesWritten).toDouble() },
        )
        binding.panelLogs.profilerReport.text = profiler.formatReport(snap)
    }

    override fun onStart() {
        super.onStart()
        DemoLogBuffer.addListener(logListener)
        ContextCompat.registerReceiver(
            this,
            vpnStatusReceiver,
            IntentFilter(KotlinTorVpnService.ACTION_STATUS),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onStop() {
        DemoLogBuffer.removeListener(logListener)
        runCatching { unregisterReceiver(vpnStatusReceiver) }
        super.onStop()
    }

    override fun onDestroy() {
        pollJob?.cancel()
        stopProfilerSampling()
        profiler.removeListener(profilerListener)
        if (mode == Mode.ROUTER) {
            lifecycleScope.launch { session.stop() }
        }
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (!useRail && binding.drawerLayout.isDrawerOpen(GravityCompat.START)) {
            binding.drawerLayout.closeDrawer(GravityCompat.START)
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    private fun setStatus(text: String) {
        binding.panelHome.status.text = text
        DemoLogBuffer.append("status", text)
        DemoFeatures.parseBootstrapProgress(text)?.let {
            binding.panelHome.bootstrapProgress.isIndeterminate = false
            binding.panelHome.bootstrapProgress.progress = it
        }
    }

    private fun updateModeChips() {
        binding.panelHome.chipIdle.isChecked = mode == Mode.IDLE
        binding.panelHome.chipRouter.isChecked = mode == Mode.ROUTER
        binding.panelHome.chipVpn.isChecked = mode == Mode.VPN
    }

    private fun refreshLogsView(scrollToEnd: Boolean) {
        val body = DemoLogBuffer.snapshot()
        binding.panelLogs.logsText.text = body.ifBlank { getString(R.string.logs_empty) }
        if (scrollToEnd) {
            binding.panelLogs.logsScroll.post {
                binding.panelLogs.logsScroll.fullScroll(View.FOCUS_DOWN)
            }
        }
    }

    private fun requestVpn() {
        if (mode == Mode.ROUTER) {
            Toast.makeText(this, "Stop the loopback router first", Toast.LENGTH_SHORT).show()
            return
        }
        binding.panelVpn.btnVpnStart.isEnabled = false
        setStatus("Requesting VPN permission…")
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPrepareLauncher.launch(prepare) else startVpnService()
    }

    private fun startVpnService() {
        mode = Mode.VPN
        setRouterUi(false)
        binding.panelHome.btnStart.isEnabled = false
        setStatus("Starting VPN…")
        val i = Intent(this, DemoVpnService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
        setVpnUi(running = true, ready = false)
        updateModeChips()
    }

    private fun stopVpn() {
        DemoLogBuffer.append("ui", "Stop VPN")
        startService(Intent(this, DemoVpnService::class.java).setAction(KotlinTorVpnService.ACTION_STOP))
        setStatus(getString(R.string.status_idle))
        binding.panelHome.ports.text = ""
        binding.panelProxies.checkResult.text = ""
        binding.panelVpn.vpnStatusDetail.text = ""
        mode = Mode.IDLE
        setVpnUi(running = false, ready = false)
        binding.panelHome.btnStart.isEnabled = true
        updateModeChips()
    }

    private fun dataDir(): Path =
        Path.of(filesDir.absolutePath, "tor-data")

    private fun startRouter() {
        if (mode == Mode.VPN) {
            Toast.makeText(this, "Stop VPN first", Toast.LENGTH_SHORT).show()
            return
        }
        setStatus("Starting…")
        binding.panelHome.bootstrapProgress.isIndeterminate = true
        binding.panelHome.btnStart.isEnabled = false
        binding.panelVpn.btnVpnStart.isEnabled = false
        val preferDnssec = binding.panelDns.switchDnssec.isChecked
        val recursive = binding.panelDns.dnsRecursive.text?.toString()?.trim().orEmpty()
            .ifBlank { "1.1.1.1:53" }
        mode = Mode.ROUTER
        updateModeChips()
        DemoLogBuffer.append("ui", "Start router dnssec=$preferDnssec recursive=$recursive")
        lifecycleScope.launch {
            runCatching {
                session.start(
                    DemoSessionOptions(
                        dataDirectory = dataDir(),
                        dnssecValidate = preferDnssec,
                        dnssecRecursive = recursive,
                        useMicrodescriptors = false,
                    ),
                )
            }.onSuccess {
                setRouterUi(true)
                refreshPorts()
                setStatus(session.bootstrapLine())
                startBootstrapPoll()
            }.onFailure { t ->
                binding.panelHome.bootstrapProgress.isIndeterminate = false
                setStatus("Error: ${t.message}")
                DemoLogBuffer.append("error", t.stackTraceToString())
                setRouterUi(false)
                mode = Mode.IDLE
                binding.panelVpn.btnVpnStart.isEnabled = true
                updateModeChips()
            }
        }
    }

    private fun stopRouter() {
        DemoLogBuffer.append("ui", "Stop router")
        pollJob?.cancel()
        pollJob = null
        lifecycleScope.launch {
            session.stop()
            binding.panelHome.ports.text = ""
            binding.panelProxies.checkResult.text = ""
            binding.panelHome.bootstrapProgress.isIndeterminate = false
            binding.panelHome.bootstrapProgress.progress = 0
            setStatus(getString(R.string.status_idle))
            mode = Mode.IDLE
            setRouterUi(false)
            binding.panelVpn.btnVpnStart.isEnabled = true
            updateModeChips()
        }
    }

    private fun startBootstrapPoll() {
        pollJob?.cancel()
        var lastLine: String? = null
        pollJob = lifecycleScope.launch {
            while (isActive) {
                if (!session.isRunning) break
                val line = session.bootstrapLine()
                if (line != lastLine) {
                    setStatus(line)
                    lastLine = line
                }
                refreshPorts()
                delay(1_000)
            }
        }
    }

    private fun refreshPorts() {
        if (!session.isRunning) return
        val p = session.ports()
        binding.panelHome.ports.text = buildString {
            appendLine("SOCKS5H   127.0.0.1:${p.socks}")
            appendLine("HTTP CONNECT 127.0.0.1:${p.http}")
            appendLine("DNSPort   127.0.0.1:${p.dns}")
            appendLine("Control   127.0.0.1:${p.control}")
            if (session.dnssecValidate()) appendLine("DNSSEC    validate → ${session.dnssecRecursive()}")
        }
    }

    private fun setRouterUi(running: Boolean) {
        binding.panelHome.btnStart.isEnabled = !running && mode != Mode.VPN
        binding.panelHome.btnStop.isEnabled = running
        binding.panelProxies.btnNewnym.isEnabled = running
        binding.panelProxies.btnCopySocks.isEnabled = running
        binding.panelProxies.btnCopyHttp.isEnabled = running
        binding.panelProxies.btnSelfCheck.isEnabled = running
        binding.panelDns.btnDnsResolve.isEnabled = running
        binding.panelCircuits.btnCircuitsRefresh.isEnabled = running
        binding.panelCircuits.switchDormant.isEnabled = running
        binding.panelOnion.btnOnionFetch.isEnabled = running
        binding.panelControl.btnControlGetInfo.isEnabled = running
        binding.panelControl.btnControlNewnym.isEnabled = running
    }

    private fun setVpnUi(running: Boolean, ready: Boolean) {
        binding.panelVpn.btnVpnStart.isEnabled = !running && mode != Mode.ROUTER
        binding.panelVpn.btnVpnStop.isEnabled = running
        binding.panelVpn.btnVpnSelfCheck.isEnabled = ready
        if (running) binding.panelHome.btnStart.isEnabled = false
        else if (mode != Mode.ROUTER) binding.panelHome.btnStart.isEnabled = true
    }

    private fun copy(text: String) {
        getSystemService<ClipboardManager>()?.setPrimaryClip(ClipData.newPlainText("proxy", text))
        Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
    }

    private fun runSocksSelfCheck() {
        binding.panelProxies.checkResult.text = "Checking via SOCKS5…"
        binding.panelProxies.btnSelfCheck.isEnabled = false
        lifecycleScope.launch {
            val result = features.socksSelfCheck()
            binding.panelProxies.checkResult.text = result
            DemoLogBuffer.append("check", result)
            binding.panelProxies.btnSelfCheck.isEnabled = session.isRunning
        }
    }

    private fun runVpnSelfCheck() {
        binding.panelVpn.vpnStatusDetail.text = "Checking via VPN path…"
        binding.panelVpn.btnVpnSelfCheck.isEnabled = false
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                DemoFeatures.httpGet("https://check.torproject.org/api/ip", Proxy.NO_PROXY)
            }
            binding.panelVpn.vpnStatusDetail.text = "VPN $result"
            DemoLogBuffer.append("check", "VPN $result")
            binding.panelVpn.btnVpnSelfCheck.isEnabled = mode == Mode.VPN
        }
    }

    private fun runDnsResolve() {
        val host = binding.panelDns.dnsHostname.text?.toString().orEmpty()
        binding.panelDns.dnsResult.text = "Resolving…"
        binding.panelDns.btnDnsResolve.isEnabled = false
        lifecycleScope.launch {
            val result = features.resolve(host)
            binding.panelDns.dnsResult.text = result
            DemoLogBuffer.append("dns", "$host → $result")
            binding.panelDns.btnDnsResolve.isEnabled = session.isRunning
        }
    }

    private fun refreshCircuitsPanel() {
        val circ = features.circuitStatusLines().joinToString("\n").ifBlank { "(no circuits)" }
        val guards = features.guardStatusLines().joinToString("\n").ifBlank { "(no guards)" }
        binding.panelCircuits.circuitsText.text = "CIRC\n$circ\n\nGUARD\n$guards"
        DemoLogBuffer.append("circ", "refreshed circuits/guards")
    }

    private fun runOnionFetch() {
        val onion = binding.panelOnion.onionAddress.text?.toString().orEmpty()
        binding.panelOnion.onionResult.text = "Fetching descriptor…"
        binding.panelOnion.btnOnionFetch.isEnabled = false
        lifecycleScope.launch {
            val result = features.fetchOnionDescriptor(onion)
            binding.panelOnion.onionResult.text = result
            DemoLogBuffer.append("hs", result.lines().firstOrNull() ?: result)
            binding.panelOnion.btnOnionFetch.isEnabled = session.isRunning
        }
    }

    private fun runControlGetInfo() {
        binding.panelControl.controlResult.text = "GETINFO…"
        binding.panelControl.btnControlGetInfo.isEnabled = false
        lifecycleScope.launch {
            val result = features.controlGetInfo()
            binding.panelControl.controlResult.text = result
            DemoLogBuffer.append("control", result.lines().firstOrNull() ?: result)
            binding.panelControl.btnControlGetInfo.isEnabled = session.isRunning
        }
    }

    private fun runControlSignal() {
        binding.panelControl.btnControlNewnym.isEnabled = false
        lifecycleScope.launch {
            val result = features.controlSignal("NEWNYM")
            binding.panelControl.controlResult.text = result
            DemoLogBuffer.append("control", "SIGNAL NEWNYM → $result")
            binding.panelControl.btnControlNewnym.isEnabled = session.isRunning
        }
    }
}
