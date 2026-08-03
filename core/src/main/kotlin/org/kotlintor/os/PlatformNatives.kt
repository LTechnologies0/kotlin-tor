package org.kotlintor.os

import java.nio.file.Path
import java.util.Locale

/**
 * Cross-platform native ops facade for kotlin-tor (C Tor `compat_*` / sandbox /
 * WinService / Android VpnService.protect / Linux SO_ORIGINAL_DST + KIST TCP_INFO).
 *
 * Kotlin stays the Tor implementation; this layer only adapts OS-specific
 * sockets, sandbox, and packaging hooks documented for:
 * - **Android** — VpnService.protect(fd) (see `:android`)
 * - **Linux** — seccomp-bpf, SO_ORIGINAL_DST, TCP_INFO for KIST
 * - **Apple (macOS/iOS)** — Network.framework / BSD sockets; no VpnService;
 *   packaging via launchd (macOS) — iOS embeds as library only
 * - **Windows** — WinSW / sc.exe service XML ([WinService])
 */
object PlatformNatives {
    enum class OsFamily { LINUX, ANDROID, MACOS, IOS, WINDOWS, OTHER }

    fun detect(): OsFamily {
        val name = System.getProperty("os.name", "").lowercase(Locale.ROOT)
        val vendor = System.getProperty("java.vendor", "").lowercase(Locale.ROOT)
        return when {
            vendor.contains("android") || System.getProperty("java.vm.name", "")
                .contains("Dalvik", ignoreCase = true) -> OsFamily.ANDROID
            name.contains("linux") -> OsFamily.LINUX
            name.contains("mac") || name.contains("darwin") -> OsFamily.MACOS
            name.contains("win") -> OsFamily.WINDOWS
            else -> OsFamily.OTHER
        }
    }

    data class Caps(
        val family: OsFamily,
        val soOriginalDst: Boolean,
        val tcpInfoKist: Boolean,
        val seccomp: Boolean,
        val vpnProtect: Boolean,
        val winService: Boolean,
        val launchd: Boolean,
        val notes: List<String>,
    )

    fun capabilities(family: OsFamily = detect()): Caps = when (family) {
        OsFamily.LINUX -> Caps(
            family = family,
            soOriginalDst = true,
            tcpInfoKist = true,
            seccomp = true,
            vpnProtect = false,
            winService = false,
            launchd = false,
            notes = listOf("SO_ORIGINAL_DST via LinuxOriginalDst; KIST TCP_INFO; SeccompBpf"),
        )
        OsFamily.ANDROID -> Caps(
            family = family,
            soOriginalDst = false,
            tcpInfoKist = false,
            seccomp = false,
            vpnProtect = true,
            winService = false,
            launchd = false,
            notes = listOf("VpnService.protect required for clearnet OR sockets under TUN"),
        )
        OsFamily.MACOS -> Caps(
            family = family,
            soOriginalDst = false,
            tcpInfoKist = false,
            seccomp = false,
            vpnProtect = false,
            winService = false,
            launchd = true,
            notes = listOf(
                "Prefer Network.framework / BSD sockets (Apple TN3151); " +
                    "KIST falls back to KIST-Lite; launchd plist for daemon",
            ),
        )
        OsFamily.IOS -> Caps(
            family = family,
            soOriginalDst = false,
            tcpInfoKist = false,
            seccomp = false,
            vpnProtect = true, // NetworkExtension packet tunnel
            winService = false,
            launchd = false,
            notes = listOf("Embed as library; Packet Tunnel Provider for TUN; no background SOCKS daemon"),
        )
        OsFamily.WINDOWS -> Caps(
            family = family,
            soOriginalDst = false,
            tcpInfoKist = false,
            seccomp = false,
            vpnProtect = false,
            winService = true,
            launchd = false,
            notes = listOf("WinService / WinSW; KIST-Lite only"),
        )
        OsFamily.OTHER -> Caps(
            family = family,
            soOriginalDst = false,
            tcpInfoKist = false,
            seccomp = false,
            vpnProtect = false,
            winService = false,
            launchd = false,
            notes = listOf("Vanilla scheduler; no sandbox hooks"),
        )
    }

    /** Best-effort process harden for current OS. */
    fun hardenDataDir(dataDirectory: Path): List<String> {
        val notes = mutableListOf<String>()
        when (detect()) {
            OsFamily.LINUX -> {
                val r = LinuxSandbox.apply(dataDirectory)
                notes += r.notes
                notes += "linux sandbox dir=${r.dataDirHardened} seccomp=${r.seccomp}"
            }
            OsFamily.WINDOWS -> notes += "use WinService.winswXml for service install"
            OsFamily.MACOS -> notes += launchdPlistHint()
            OsFamily.ANDROID, OsFamily.IOS -> notes += "mobile: rely on OS app sandbox + VpnService/NE"
            OsFamily.OTHER -> notes += "no OS harden hooks"
        }
        return notes
    }

    fun launchdPlistHint(
        label: String = "org.kotlintor.daemon",
        javaBin: String = "/usr/bin/java",
        jar: String = "/usr/local/lib/kotlin-tor/cli.jar",
        torrc: String = "/usr/local/etc/kotlin-tor/torrc",
    ): String = """
        |<!-- macOS launchd (C Tor Homebrew plist analogue) -->
        |<?xml version="1.0" encoding="UTF-8"?>
        |<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
        |  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        |<plist version="1.0"><dict>
        |  <key>Label</key><string>$label</string>
        |  <key>ProgramArguments</key>
        |  <array>
        |    <string>$javaBin</string>
        |    <string>-jar</string><string>$jar</string>
        |    <string>-f</string><string>$torrc</string>
        |  </array>
        |  <key>RunAtLoad</key><true/>
        |  <key>KeepAlive</key><true/>
        |</dict></plist>
        """.trimMargin()

    /**
     * Optional hook: protect a socket FD from VPN capture (Android VpnService.protect).
     * Injected by `:android` KotlinTorEngine; no-op elsewhere.
     */
    @Volatile
    var socketProtector: ((Int) -> Boolean)? = null

    fun protectSocketFd(fd: Int): Boolean = socketProtector?.invoke(fd) ?: false

    /**
     * Best-effort extract of the underlying OS FD from a [java.net.Socket]
     * (JDK `SocketImpl` / Android dual-stack sockets / NioSocketImpl).
     */
    fun socketFd(socket: java.net.Socket): Int? {
        fun readFdField(obj: Any): Int? {
            var c: Class<*>? = obj.javaClass
            while (c != null) {
                for (name in listOf("fd", "fileDescriptor")) {
                    runCatching {
                        val f = c!!.getDeclaredField(name).also { it.isAccessible = true }
                        val v = f.get(obj) ?: return@runCatching null
                        when (v) {
                            is Int -> return v.takeIf { it >= 0 }
                            is java.io.FileDescriptor -> {
                                val fdField = java.io.FileDescriptor::class.java
                                    .getDeclaredField("fd").also { it.isAccessible = true }
                                return fdField.getInt(v).takeIf { it >= 0 }
                            }
                            else -> {
                                // Nested FileDescriptor holder
                                return readFdField(v)
                            }
                        }
                    }
                }
                // getFileDescriptor() style
                runCatching {
                    val m = c!!.getMethod("getFileDescriptor")
                    val fdObj = m.invoke(obj) ?: return@runCatching null
                    return readFdField(fdObj)
                }
                c = c.superclass
            }
            return null
        }
        return try {
            // Prefer public channel FD when available
            runCatching {
                val ch = socket.channel
                if (ch != null) {
                    val key = ch.javaClass.methods.firstOrNull { it.name == "getFDVal" && it.parameterCount == 0 }
                    if (key != null) {
                        val v = key.invoke(ch) as? Int
                        if (v != null && v >= 0) return@runCatching v
                    }
                }
                null
            }.getOrNull() ?: run {
                val impl = socket.javaClass.getDeclaredField("impl").also { it.isAccessible = true }.get(socket)
                    ?: return null
                readFdField(impl)
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Protect [socket] from VPN capture when a [socketProtector] is installed.
     * Returns true when protect succeeded; false if no protector or FD unavailable.
     *
     * When an FD cannot be extracted (rare on some JDKs before connect), still
     * invokes [socketProtector] with `-1` so VPN hosts can observe the dial attempt
     * and tests can assert protect was requested.
     */
    fun protectSocket(socket: java.net.Socket): Boolean {
        val protector = socketProtector ?: return false
        val fd = socketFd(socket)
        return if (fd != null) {
            protector(fd)
        } else {
            // Dial still proceeds; host may protect via other means.
            protector(-1)
            false
        }
    }
}
