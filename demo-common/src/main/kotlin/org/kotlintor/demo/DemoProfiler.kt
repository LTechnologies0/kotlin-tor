package org.kotlintor.demo

import java.lang.management.ManagementFactory
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.math.max

/**
 * Live process + optional Tor session profiler for demo shells.
 * Samples heap, threads, GC, CPU (when MXBeans allow), and Tor traffic/circuits.
 */
data class ProfilerSample(
    val epochMs: Long,
    val sampleCostNs: Long,
    val heapUsedBytes: Long,
    val heapCommittedBytes: Long,
    val heapMaxBytes: Long,
    val nonHeapUsedBytes: Long?,
    val threadCount: Int,
    val daemonThreadCount: Int,
    val peakThreadCount: Int,
    val gcCollectionCount: Long,
    val gcTimeMs: Long,
    val processCpuLoad: Double?,
    val systemCpuLoad: Double?,
    val availableProcessors: Int,
    val jvmUptimeMs: Long,
    val torRunning: Boolean,
    val torCircuitCount: Int,
    val torBytesRead: Long,
    val torBytesWritten: Long,
    val torBootstrapProgress: Int?,
    val torBootstrapLine: String?,
)

data class ProfilerPeaks(
    val heapUsedBytes: Long = 0,
    val threadCount: Int = 0,
    val processCpuLoad: Double = 0.0,
    val torBytesRead: Long = 0,
    val torBytesWritten: Long = 0,
)

data class ProfilerSnapshot(
    val live: Boolean,
    val intervalMs: Long,
    val sampleCount: Int,
    val latest: ProfilerSample?,
    val peaks: ProfilerPeaks,
    val history: List<ProfilerSample>,
    val heapDeltaBytesPerSec: Double,
    val readBytesPerSec: Double,
    val writeBytesPerSec: Double,
    val gcDeltaMsPerSec: Double,
)

/**
 * Ring-buffer profiler. Call [start] while the Logs/Profiler tab is visible;
 * [stop] when leaving or destroying the host.
 */
class DemoProfiler(
    private val historyCapacity: Int = 120,
) {
    private val lock = Any()
    private val history = ArrayDeque<ProfilerSample>(historyCapacity)
    private val listeners = CopyOnWriteArrayList<(ProfilerSnapshot) -> Unit>()
    private val sampling = AtomicBoolean(false)
    private val intervalMs = AtomicLong(1_000)
    private val peaks = AtomicReference(ProfilerPeaks())
    private var sampler: Thread? = null
    private var sessionProvider: (() -> DemoSession?)? = null
    private val startEpochMs = System.currentTimeMillis()

    fun isLive(): Boolean = sampling.get()

    fun intervalMs(): Long = intervalMs.get()

    fun setIntervalMs(ms: Long) {
        intervalMs.set(ms.coerceIn(250L, 10_000L))
    }

    fun start(sessionProvider: () -> DemoSession? = { null }, intervalMs: Long = 1_000) {
        this.sessionProvider = sessionProvider
        setIntervalMs(intervalMs)
        if (!sampling.compareAndSet(false, true)) return
        sampler = thread(name = "demo-profiler", isDaemon = true) {
            while (sampling.get()) {
                val snap = captureAndStore()
                for (l in listeners) runCatching { l(snap) }
                val sleep = this.intervalMs.get().coerceAtLeast(100L)
                try {
                    Thread.sleep(sleep)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
    }

    fun stop() {
        if (!sampling.compareAndSet(true, false)) return
        sampler?.interrupt()
        sampler = null
    }

    fun resetPeaks() {
        peaks.set(ProfilerPeaks())
        val latest = synchronized(lock) { history.lastOrNull() }
        if (latest != null) updatePeaks(latest)
        notifyListeners()
    }

    fun clearHistory() {
        synchronized(lock) { history.clear() }
        peaks.set(ProfilerPeaks())
        notifyListeners()
    }

    fun addListener(listener: (ProfilerSnapshot) -> Unit) {
        listeners += listener
    }

    fun removeListener(listener: (ProfilerSnapshot) -> Unit) {
        listeners -= listener
    }

    fun snapshot(): ProfilerSnapshot = synchronized(lock) { buildSnapshotLocked() }

    /** One-shot sample without appending to history (for idle display). */
    fun sampleOnce(session: DemoSession? = sessionProvider?.invoke()): ProfilerSample =
        collectSample(session)

    fun formatReport(snap: ProfilerSnapshot = snapshot()): String {
        val s = snap.latest ?: return "No samples yet."
        return buildString {
            appendLine("=== kotlin-tor demo profiler ===")
            appendLine("live=${snap.live} interval=${snap.intervalMs}ms samples=${snap.sampleCount}")
            appendLine("cost=${"%.2f".format(s.sampleCostNs / 1_000_000.0)}ms uptime=${formatDuration(s.jvmUptimeMs)}")
            appendLine()
            appendLine("-- Heap --")
            appendLine("used=${formatBytes(s.heapUsedBytes)} / committed=${formatBytes(s.heapCommittedBytes)} / max=${formatBytes(s.heapMaxBytes)}")
            appendLine("usage=${"%.1f".format(heapRatio(s) * 100)}%  Δ=${formatRate(snap.heapDeltaBytesPerSec)}/s  peak=${formatBytes(snap.peaks.heapUsedBytes)}")
            s.nonHeapUsedBytes?.let { appendLine("non-heap=${formatBytes(it)}") }
            appendLine()
            appendLine("-- Threads --")
            appendLine("live=${s.threadCount} daemon=${s.daemonThreadCount} peak=${s.peakThreadCount} (session peak=${snap.peaks.threadCount})")
            appendLine("cpus=${s.availableProcessors}")
            appendLine()
            appendLine("-- GC --")
            appendLine("collections=${s.gcCollectionCount} time=${s.gcTimeMs}ms  Δ=${"%.2f".format(snap.gcDeltaMsPerSec)}ms/s")
            appendLine()
            appendLine("-- CPU --")
            appendLine("process=${formatCpu(s.processCpuLoad)} (peak=${formatCpu(snap.peaks.processCpuLoad)}) system=${formatCpu(s.systemCpuLoad)}")
            appendLine()
            appendLine("-- Tor --")
            if (s.torRunning) {
                appendLine("circuits=${s.torCircuitCount}")
                appendLine("read=${formatBytes(s.torBytesRead)} (${formatRate(snap.readBytesPerSec)}/s) peak=${formatBytes(snap.peaks.torBytesRead)}")
                appendLine("written=${formatBytes(s.torBytesWritten)} (${formatRate(snap.writeBytesPerSec)}/s) peak=${formatBytes(snap.peaks.torBytesWritten)}")
                appendLine("bootstrap=${s.torBootstrapProgress ?: "?"} ${s.torBootstrapLine.orEmpty()}")
            } else {
                appendLine("session not running")
            }
        }.trimEnd()
    }

    private fun captureAndStore(): ProfilerSnapshot {
        val sample = collectSample(sessionProvider?.invoke())
        synchronized(lock) {
            history.addLast(sample)
            while (history.size > historyCapacity) history.removeFirst()
            updatePeaks(sample)
            return buildSnapshotLocked()
        }
    }

    private fun notifyListeners() {
        val snap = snapshot()
        for (l in listeners) runCatching { l(snap) }
    }

    private fun updatePeaks(s: ProfilerSample) {
        peaks.updateAndGet { p ->
            ProfilerPeaks(
                heapUsedBytes = max(p.heapUsedBytes, s.heapUsedBytes),
                threadCount = max(p.threadCount, s.threadCount),
                processCpuLoad = max(p.processCpuLoad, s.processCpuLoad ?: 0.0),
                torBytesRead = max(p.torBytesRead, s.torBytesRead),
                torBytesWritten = max(p.torBytesWritten, s.torBytesWritten),
            )
        }
    }

    private fun buildSnapshotLocked(): ProfilerSnapshot {
        val list = history.toList()
        val latest = list.lastOrNull()
        val prev = if (list.size >= 2) list[list.size - 2] else null
        val dtSec = if (latest != null && prev != null) {
            ((latest.epochMs - prev.epochMs) / 1000.0).coerceAtLeast(0.001)
        } else {
            1.0
        }
        return ProfilerSnapshot(
            live = sampling.get(),
            intervalMs = intervalMs.get(),
            sampleCount = list.size,
            latest = latest,
            peaks = peaks.get(),
            history = list,
            heapDeltaBytesPerSec = if (latest != null && prev != null) {
                (latest.heapUsedBytes - prev.heapUsedBytes) / dtSec
            } else {
                0.0
            },
            readBytesPerSec = if (latest != null && prev != null) {
                (latest.torBytesRead - prev.torBytesRead) / dtSec
            } else {
                0.0
            },
            writeBytesPerSec = if (latest != null && prev != null) {
                (latest.torBytesWritten - prev.torBytesWritten) / dtSec
            } else {
                0.0
            },
            gcDeltaMsPerSec = if (latest != null && prev != null) {
                (latest.gcTimeMs - prev.gcTimeMs) / dtSec
            } else {
                0.0
            },
        )
    }

    private fun collectSample(session: DemoSession?): ProfilerSample {
        val t0 = System.nanoTime()
        val rt = Runtime.getRuntime()
        val heapMax = rt.maxMemory()
        val heapCommitted = rt.totalMemory()
        val heapUsed = heapCommitted - rt.freeMemory()

        var nonHeap: Long? = null
        var threadCount = Thread.activeCount()
        var daemonCount = 0
        var peakThreads = threadCount
        var gcCount = 0L
        var gcTime = 0L
        var processCpu: Double? = null
        var systemCpu: Double? = null
        var uptime = System.currentTimeMillis() - startEpochMs
        val cpus = rt.availableProcessors().coerceAtLeast(1)

        runCatching {
            val threadBean = ManagementFactory.getThreadMXBean()
            threadCount = threadBean.threadCount
            daemonCount = threadBean.daemonThreadCount
            peakThreads = threadBean.peakThreadCount
        }
        runCatching {
            val mem = ManagementFactory.getMemoryMXBean()
            nonHeap = mem.nonHeapMemoryUsage.used
        }
        runCatching {
            for (gc in ManagementFactory.getGarbageCollectorMXBeans()) {
                val c = gc.collectionCount
                val t = gc.collectionTime
                if (c >= 0) gcCount += c
                if (t >= 0) gcTime += t
            }
        }
        runCatching {
            val rtBean = ManagementFactory.getRuntimeMXBean()
            uptime = rtBean.uptime
        }
        runCatching {
            val os = ManagementFactory.getOperatingSystemMXBean()
            // Prefer HotSpot extension via reflection (desktop); Android often lacks it.
            val cls = os.javaClass
            processCpu = cls.methods.firstOrNull { it.name == "getProcessCpuLoad" && it.parameterCount == 0 }
                ?.invoke(os) as? Double
            systemCpu = cls.methods.firstOrNull { it.name == "getCpuLoad" && it.parameterCount == 0 }
                ?.invoke(os) as? Double
                ?: (cls.methods.firstOrNull { it.name == "getSystemCpuLoad" && it.parameterCount == 0 }
                    ?.invoke(os) as? Double)
            if (processCpu != null && processCpu!! < 0) processCpu = null
            if (systemCpu != null && systemCpu!! < 0) systemCpu = null
        }

        val torRunning = session?.isRunning == true
        val daemon = session?.torDaemon
        val bootstrapLine = if (torRunning) session?.bootstrapLine() else null
        val cost = System.nanoTime() - t0
        return ProfilerSample(
            epochMs = System.currentTimeMillis(),
            sampleCostNs = cost,
            heapUsedBytes = heapUsed.coerceAtLeast(0),
            heapCommittedBytes = heapCommitted.coerceAtLeast(0),
            heapMaxBytes = heapMax.coerceAtLeast(0),
            nonHeapUsedBytes = nonHeap,
            threadCount = threadCount,
            daemonThreadCount = daemonCount,
            peakThreadCount = peakThreads,
            gcCollectionCount = gcCount,
            gcTimeMs = gcTime,
            processCpuLoad = processCpu,
            systemCpuLoad = systemCpu,
            availableProcessors = cpus,
            jvmUptimeMs = uptime,
            torRunning = torRunning,
            torCircuitCount = if (torRunning) daemon?.openCircuitCount() ?: 0 else 0,
            torBytesRead = if (torRunning) daemon?.bytesRead() ?: 0L else 0L,
            torBytesWritten = if (torRunning) daemon?.bytesWritten() ?: 0L else 0L,
            torBootstrapProgress = bootstrapLine?.let { DemoFeatures.parseBootstrapProgress(it) },
            torBootstrapLine = bootstrapLine,
        )
    }

    companion object {
        fun heapRatio(s: ProfilerSample): Double {
            val denom = when {
                s.heapMaxBytes > 0 -> s.heapMaxBytes
                s.heapCommittedBytes > 0 -> s.heapCommittedBytes
                else -> 1L
            }
            return (s.heapUsedBytes.toDouble() / denom).coerceIn(0.0, 1.0)
        }

        fun formatBytes(n: Long): String {
            val v = n.toDouble()
            val abs = kotlin.math.abs(v)
            return when {
                abs >= 1L shl 30 -> "%.2f GiB".format(v / (1L shl 30))
                abs >= 1L shl 20 -> "%.2f MiB".format(v / (1L shl 20))
                abs >= 1L shl 10 -> "%.1f KiB".format(v / (1L shl 10))
                else -> "$n B"
            }
        }

        fun formatRate(bytesPerSec: Double): String {
            val sign = if (bytesPerSec < 0) "-" else ""
            return sign + formatBytes(kotlin.math.abs(bytesPerSec).toLong())
        }

        fun formatCpu(load: Double?): String =
            if (load == null) "n/a" else "%.1f%%".format(load * 100.0)

        fun formatDuration(ms: Long): String {
            val s = ms / 1000
            val h = s / 3600
            val m = (s % 3600) / 60
            val sec = s % 60
            return if (h > 0) "%dh %02dm %02ds".format(h, m, sec) else "%dm %02ds".format(m, sec)
        }
    }
}
