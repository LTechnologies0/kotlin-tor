package org.kotlintor.os

import org.kotlintor.link.KistMath
import java.io.File
import java.net.Socket

/**
 * Linux `TCP_INFO` + `SIOCOUTQNSD` probe for KIST (C Tor `scheduler_kist.c`).
 *
 * The python3 `ProcessBuilder` path below is **debug / opt-in only** and must **not**
 * run on the OR write hot path by default. Set env `KOTLIN_TOR_KIST_PYTHON=1` to enable
 * full KIST probes; otherwise callers use [KistMath.liteLimit] / KIST_LITE.
 *
 * Uses python3 ctypes (same pattern as [org.kotlintor.proxy.LinuxOriginalDst]) so
 * we avoid JNI; returns null → callers fall back to [KistMath.liteLimit].
 */
object LinuxTcpInfo {
    private const val ENV_FULL_KIST = "KOTLIN_TOR_KIST_PYTHON"

    data class Info(
        val sndCwnd: Long,
        val unacked: Long,
        val sndMss: Long,
        val notSent: Long,
    ) {
        fun toKist(): KistMath.SocketInfo =
            KistMath.SocketInfo(cwnd = sndCwnd, unacked = unacked, mss = sndMss, notSent = notSent)
    }

    /**
     * True only when full-KIST python probing is explicitly enabled **and** a python3
     * interpreter exists. Presence of `/usr/bin/python3` alone is not sufficient.
     */
    fun isFullKistEnabled(): Boolean {
        val flag = System.getenv(ENV_FULL_KIST)?.trim()?.lowercase()
        if (flag != "1" && flag != "true" && flag != "yes") return false
        return File("/usr/bin/python3").canExecute() || File("/bin/python3").canExecute()
    }

    /** Alias for [isFullKistEnabled] — python3 alone does not mean TCP_INFO is available. */
    fun isAvailable(): Boolean = isFullKistEnabled()

    fun query(socket: Socket): Info? {
        val fd = fileDescriptor(socket) ?: return null
        return queryFd(fd)
    }

    fun queryFd(fd: Int): Info? {
        if (fd < 0) return null
        if (!isFullKistEnabled()) return null
        // Layout is arch-dependent; read named fields via ctypes Structure on Linux.
        val py = """
import ctypes, ctypes.util, sys
fd=int(sys.argv[1])
libc=ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6')
SOL_TCP=6
TCP_INFO=11
SIOCOUTQNSD=0x894B
class TcpInfo(ctypes.Structure):
    _fields_=[('tcpi_state',ctypes.c_uint8),('tcpi_ca_state',ctypes.c_uint8),
      ('tcpi_retransmits',ctypes.c_uint8),('tcpi_probes',ctypes.c_uint8),
      ('tcpi_backoff',ctypes.c_uint8),('tcpi_options',ctypes.c_uint8),
      ('tcpi_snd_wscale',ctypes.c_uint8,4),('tcpi_rcv_wscale',ctypes.c_uint8,4),
      ('tcpi_rto',ctypes.c_uint32),('tcpi_ato',ctypes.c_uint32),
      ('tcpi_snd_mss',ctypes.c_uint32),('tcpi_rcv_mss',ctypes.c_uint32),
      ('tcpi_unacked',ctypes.c_uint32),('tcpi_sacked',ctypes.c_uint32),
      ('tcpi_lost',ctypes.c_uint32),('tcpi_retrans',ctypes.c_uint32),
      ('tcpi_fackets',ctypes.c_uint32),
      ('tcpi_last_data_sent',ctypes.c_uint32),('tcpi_last_ack_sent',ctypes.c_uint32),
      ('tcpi_last_data_recv',ctypes.c_uint32),('tcpi_last_ack_recv',ctypes.c_uint32),
      ('tcpi_pmtu',ctypes.c_uint32),('tcpi_rcv_ssthresh',ctypes.c_uint32),
      ('tcpi_rtt',ctypes.c_uint32),('tcpi_rttvar',ctypes.c_uint32),
      ('tcpi_snd_ssthresh',ctypes.c_uint32),('tcpi_snd_cwnd',ctypes.c_uint32),
      ('tcpi_advmss',ctypes.c_uint32),('tcpi_reordering',ctypes.c_uint32)]
info=TcpInfo(); sz=ctypes.c_uint32(ctypes.sizeof(info))
r=libc.getsockopt(fd, SOL_TCP, TCP_INFO, ctypes.byref(info), ctypes.byref(sz))
if r!=0: sys.exit(2)
notsent=ctypes.c_int(0)
# ioctl may fail on some kernels — treat as 0
try:
  import fcntl, termios, struct
  # prefer libc.ioctl
  r2=libc.ioctl(fd, SIOCOUTQNSD, ctypes.byref(notsent))
  if r2!=0: notsent.value=0
except Exception:
  notsent.value=0
print(f'{info.tcpi_snd_cwnd} {info.tcpi_unacked} {info.tcpi_snd_mss} {notsent.value}')
        """.trimIndent()
        return try {
            val pb = ProcessBuilder("python3", "-c", py, fd.toString())
            pb.redirectErrorStream(true)
            val proc = pb.start()
            val out = proc.inputStream.bufferedReader().readText().trim()
            if (!proc.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) || proc.exitValue() != 0) {
                return null
            }
            val p = out.split(Regex("\\s+"))
            if (p.size < 4) return null
            Info(
                sndCwnd = p[0].toLong(),
                unacked = p[1].toLong(),
                sndMss = p[2].toLong().coerceAtLeast(1),
                notSent = p[3].toLong().coerceAtLeast(0),
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun fileDescriptor(socket: Socket): Int? = try {
        val impl = socket.javaClass.getDeclaredField("impl").also { it.isAccessible = true }.get(socket)
            ?: return null
        val fdObj = impl.javaClass.getMethod("getFileDescriptor").invoke(impl) ?: return null
        fdObj.javaClass.getDeclaredField("fd").also { it.isAccessible = true }.getInt(fdObj)
    } catch (_: Exception) {
        null
    }
}
