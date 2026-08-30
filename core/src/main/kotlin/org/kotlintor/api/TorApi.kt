package org.kotlintor.api

import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.channels.ServerSocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicLong

/**
 * Embedding API surface (C Tor `tor_api.c` / `tor_api.h`).
 *
 * Inventory: `L1:feature/api/tor_api.c`
 *
 * Mirrors `tor_main_configuration_new`, `set_command_line`,
 * `setup_control_socket`, `free`, `tor_api_get_provider_version`,
 * `tor_run_main`, and deprecated `tor_main`.
 */
class TorMainConfiguration {
    /** C Tor `argc` / `argv` (not owned until [setCommandLine] copies refs). */
    var argc: Int = 1
        private set
    var argv: Array<String> = arrayOf("tor")
        private set

    /** Owned args appended by [setupControlSocket] (`argv_owned` / `argc_owned`). */
    private val ownedArgs = mutableListOf<String>()

    /** Torrc lines from [addTorrcLine] (kotlin convenience; folded into [buildConfig]). */
    private val torrc = StringBuilder()

    var dataDirectory: Path? = null

    /**
     * C Tor `owning_controller_socket` — JVM side uses a synthetic id tied to
     * a unix-domain accept socket (see [setupControlSocket]).
     */
    var owningControllerSocket: Long = INVALID_CONTROL_SOCKET
        private set

    private var owningServer: ServerSocketChannel? = null
    private var owningPath: Path? = null
    private var freed = false

    fun addTorrcLine(line: String) {
        check(!freed) { "configuration already freed" }
        torrc.append(line.trimEnd()).append('\n')
    }

    /**
     * C Tor `tor_main_configuration_set_command_line`.
     * @return 0 on success, -1 if freed / null-like
     */
    fun torMainConfigurationSetCommandLine(args: Array<String>): Int = setCommandLine(args)

    fun setCommandLine(args: Array<String>): Int {
        if (freed) return -1
        argc = args.size
        argv = args.copyOf()
        return 0
    }

    /**
     * C Tor `tor_main_configuration_setup_control_socket`.
     *
     * Creates a unix-domain listening socket and owns `__OwningControllerFD`
     * plus a synthetic fd id (channel hash). Returns the controller-side id
     * (C Tor returns the peer end of a socketpair).
     */
    fun torMainConfigurationSetupControlSocket(): Long = setupControlSocket()

    fun setupControlSocket(): Long {
        if (freed) return INVALID_CONTROL_SOCKET
        if (owningControllerSocket != INVALID_CONTROL_SOCKET) return INVALID_CONTROL_SOCKET
        val dir = Files.createTempDirectory("ktor-owning-ctrl")
        val sockPath = dir.resolve("owning.sock")
        val server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
        server.bind(UnixDomainSocketAddress.of(sockPath))
        owningServer = server
        owningPath = sockPath
        val id = NEXT_FD.incrementAndGet()
        ownedArgs += "__OwningControllerFD"
        ownedArgs += id.toString()
        owningControllerSocket = id
        return id
    }

    fun ownedArguments(): List<String> = ownedArgs.toList()

    /**
     * Build [TorConfig] from torrc lines + argv flags (`-f`, `--DataDirectory`,
     * bare `Key Value` pairs) and owned `__OwningControllerFD`.
     */
    fun buildConfig(): TorConfig {
        check(!freed) { "configuration already freed" }
        val dir = dataDirectory ?: Path.of(".").toAbsolutePath().normalize()
        val sb = StringBuilder(torrc)
        var i = 1
        while (i < argv.size) {
            val a = argv[i]
            when {
                a == "-f" && i + 1 < argv.size -> {
                    sb.append(Files.readString(Path.of(argv[i + 1])))
                    if (!sb.endsWith("\n")) sb.append('\n')
                    i += 2
                }
                a.startsWith("--") && a.contains('=') -> {
                    val key = a.removePrefix("--").substringBefore('=')
                    val value = a.substringAfter('=')
                    sb.append(key).append(' ').append(value).append('\n')
                    i++
                }
                a.startsWith("--") && i + 1 < argv.size -> {
                    sb.append(a.removePrefix("--")).append(' ').append(argv[i + 1]).append('\n')
                    i += 2
                }
                !a.startsWith("-") && i + 1 < argv.size && !argv[i + 1].startsWith("-") -> {
                    sb.append(a).append(' ').append(argv[i + 1]).append('\n')
                    i += 2
                }
                else -> i++
            }
        }
        for (j in ownedArgs.indices step 2) {
            if (j + 1 < ownedArgs.size) {
                sb.append(ownedArgs[j].removePrefix("__")).append(' ').append(ownedArgs[j + 1]).append('\n')
            }
        }
        if (dataDirectory != null && !sb.contains("DataDirectory")) {
            sb.append("DataDirectory ").append(dir).append('\n')
        }
        return TorrcParser.parse(sb.toString(), dir)
    }

    /** C Tor `tor_main_configuration_free`. */
    fun torMainConfigurationFree() = free()

    fun free() {
        if (freed) return
        freed = true
        ownedArgs.clear()
        runCatching { owningServer?.close() }
        owningServer = null
        owningPath?.let { p ->
            runCatching { Files.deleteIfExists(p) }
            runCatching { Files.deleteIfExists(p.parent) }
        }
        owningPath = null
        owningControllerSocket = INVALID_CONTROL_SOCKET
    }

    companion object {
        const val INVALID_CONTROL_SOCKET: Long = -1L
        private val NEXT_FD = AtomicLong(10_000)
    }
}

/** Backward-compatible alias used by older call sites / tests. */
typealias TorApiConfiguration = TorMainConfiguration

object TorApi {
    /** C Tor `tor_main_configuration_new`. */
    fun newConfiguration(): TorMainConfiguration = TorMainConfiguration()

    /** C Tor `tor_main_configuration_new` (explicit symbol alias). */
    fun torMainConfigurationNew(): TorMainConfiguration = newConfiguration()

    /** Library / package version string (kotlin-tor). */
    fun version(): String = "0.1.0-SNAPSHOT"

    /** C Tor `tor_api_get_provider_version` → `"tor " VERSION`. */
    fun providerVersion(): String = "tor ${version()}"

    fun torApiGetProviderVersion(): String = providerVersion()

    /**
     * C Tor `tor_run_main`.
     *
     * Builds config from [cfg]; when [dryRun] is true (default for embed tests),
     * validates ownership / parse and returns 0 without blocking a daemon.
     * When [dryRun] is false, starts [org.kotlintor.TorDaemon] with
     * `DisableNetwork` forced if already set, runs until [stopAfterMs], then stops.
     */
    fun runMain(cfg: TorMainConfiguration, dryRun: Boolean = true, stopAfterMs: Long = 0): Int {
        val config = try {
            cfg.buildConfig()
        } catch (_: Exception) {
            return 1
        }
        if (dryRun) {
            // Ownership integrity: owning fd (if any) must appear in process opts.
            val owned = cfg.ownedArguments()
            if (owned.isNotEmpty()) {
                val fd = config.process.owningControllerFd
                if (fd == null || fd == TorMainConfiguration.INVALID_CONTROL_SOCKET) return 1
            }
            return 0
        }
        return try {
            val daemon = org.kotlintor.TorDaemon(config)
            kotlinx.coroutines.runBlocking {
                daemon.start(buildCircuit = false)
                if (stopAfterMs > 0) {
                    kotlinx.coroutines.delay(stopAfterMs)
                }
                daemon.stop()
            }
            0
        } catch (_: Exception) {
            1
        }
    }

    fun torRunMain(cfg: TorMainConfiguration, dryRun: Boolean = true, stopAfterMs: Long = 0): Int =
        runMain(cfg, dryRun, stopAfterMs)

    /**
     * C Tor `tor_main` (deprecated embed path): new cfg → set_command_line → run_main → free.
     */
    fun main(args: Array<String>, dryRun: Boolean = true): Int {
        val cfg = newConfiguration()
        if (cfg.setCommandLine(args) < 0) {
            cfg.free()
            return 1
        }
        val rv = runMain(cfg, dryRun = dryRun)
        cfg.free()
        return rv
    }

    fun torMain(args: Array<String>, dryRun: Boolean = true): Int = main(args, dryRun)
}
