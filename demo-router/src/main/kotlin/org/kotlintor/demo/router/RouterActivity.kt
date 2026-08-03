package org.kotlintor.demo.router

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.getSystemService
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kotlintor.android.KotlinTorEngine
import org.kotlintor.config.ListenSpec
import org.kotlintor.demo.router.databinding.ActivityRouterBinding
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * Loopback Tor router demo: SOCKS5H + HTTP CONNECT + DNSPort + ControlPort.
 * No VpnService / TUN.
 */
class RouterActivity : AppCompatActivity() {
    private lateinit var binding: ActivityRouterBinding
    private var engine: KotlinTorEngine? = null
    private var pollJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityRouterBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = getString(R.string.app_name)

        binding.btnStart.setOnClickListener { startRouter() }
        binding.btnStop.setOnClickListener { stopRouter() }
        binding.btnNewnym.setOnClickListener {
            engine?.newnym()
            Toast.makeText(this, "NEWNYM signaled", Toast.LENGTH_SHORT).show()
        }
        binding.btnCopySocks.setOnClickListener {
            val e = engine ?: return@setOnClickListener
            copy("socks5h://127.0.0.1:${e.socksPort}")
        }
        binding.btnCopyHttp.setOnClickListener {
            val e = engine ?: return@setOnClickListener
            copy("http://127.0.0.1:${e.httpConnectPort}")
        }
        binding.btnSelfCheck.setOnClickListener { runSelfCheck() }
        setRunningUi(false)
    }

    override fun onDestroy() {
        pollJob?.cancel()
        engine?.stop()
        engine = null
        super.onDestroy()
    }

    private fun startRouter() {
        binding.status.text = "Starting…"
        binding.btnStart.isEnabled = false
        val cfg = KotlinTorEngine.routerDefaultConfig(this).copy(
            httpTunnelPort = ListenSpec("127.0.0.1", 0),
            dnsPort = ListenSpec("127.0.0.1", 0),
            cookieAuthentication = true,
        )
        val eng = KotlinTorEngine(this, cfg)
        engine = eng
        eng.startWithPorts(
            socks = ListenSpec("127.0.0.1", 0),
            dns = ListenSpec("127.0.0.1", 0),
            httpTunnel = ListenSpec("127.0.0.1", 0),
            controlListen = ListenSpec("127.0.0.1", 0),
            onReady = {
                runOnUiThread {
                    setRunningUi(true)
                    refreshPorts()
                    binding.status.text = eng.bootstrapLine
                    startBootstrapPoll()
                }
            },
            onError = { t ->
                runOnUiThread {
                    binding.status.text = "Error: ${t.message}"
                    setRunningUi(false)
                    engine = null
                    binding.btnStart.isEnabled = true
                }
            },
        )
    }

    private fun stopRouter() {
        pollJob?.cancel()
        pollJob = null
        engine?.stop()
        engine = null
        binding.ports.text = ""
        binding.checkResult.text = ""
        binding.status.text = getString(R.string.status_idle)
        setRunningUi(false)
    }

    private fun startBootstrapPoll() {
        pollJob?.cancel()
        pollJob = lifecycleScope.launch {
            while (isActive) {
                val e = engine
                if (e == null || !e.isRunning) break
                binding.status.text = e.bootstrapLine
                refreshPorts()
                delay(1_000)
            }
        }
    }

    private fun refreshPorts() {
        val e = engine ?: return
        binding.ports.text = buildString {
            appendLine("SOCKS5H   127.0.0.1:${e.socksPort}")
            appendLine("HTTP CONNECT 127.0.0.1:${e.httpConnectPort}")
            appendLine("DNSPort   127.0.0.1:${e.dnsPortBound}")
            appendLine("Control   127.0.0.1:${e.controlPort}")
        }
    }

    private fun setRunningUi(running: Boolean) {
        binding.btnStart.isEnabled = !running
        binding.btnStop.isEnabled = running
        binding.btnNewnym.isEnabled = running
        binding.btnCopySocks.isEnabled = running
        binding.btnCopyHttp.isEnabled = running
        binding.btnSelfCheck.isEnabled = running
    }

    private fun copy(text: String) {
        getSystemService<ClipboardManager>()?.setPrimaryClip(ClipData.newPlainText("proxy", text))
        Toast.makeText(this, "Copied: $text", Toast.LENGTH_SHORT).show()
    }

    private fun runSelfCheck() {
        val e = engine ?: return
        val port = e.socksPort
        if (port <= 0) {
            binding.checkResult.text = "No SOCKS port"
            return
        }
        binding.checkResult.text = "Checking via SOCKS5…"
        binding.btnSelfCheck.isEnabled = false
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", port))
                    val url = URL("https://check.torproject.org/api/ip")
                    val conn = url.openConnection(proxy) as HttpURLConnection
                    conn.connectTimeout = 30_000
                    conn.readTimeout = 30_000
                    conn.requestMethod = "GET"
                    conn.inputStream.bufferedReader().use { it.readText() }
                }.fold(
                    onSuccess = { body -> "OK: $body" },
                    onFailure = { t -> "Fail: ${t.javaClass.simpleName}: ${t.message}" },
                )
            }
            binding.checkResult.text = result
            binding.btnSelfCheck.isEnabled = engine?.isRunning == true
        }
    }
}
