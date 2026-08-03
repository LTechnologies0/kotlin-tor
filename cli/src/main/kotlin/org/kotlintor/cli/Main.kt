package org.kotlintor.cli

import kotlinx.coroutines.runBlocking
import org.kotlintor.TorDaemon
import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
import org.kotlintor.control.ControlServer
import org.kotlintor.proxy.DnsPortServer
import org.kotlintor.proxy.Socks5Server
import org.kotlintor.proxy.TransparentProxy
import org.kotlintor.proxy.UdpTorGatewayServer
import java.nio.file.Files
import java.nio.file.Path
import kotlin.system.exitProcess

fun main(args: Array<String>) = runBlocking {
    val cmd = args.firstOrNull() ?: "daemon"
    when (cmd) {
        "daemon", "start" -> runDaemon(args.drop(1))
        "bootstrap" -> runBootstrap(args.drop(1))
        "debug-create" -> {
            var data = Path.of("data")
            val a = args.drop(1)
            var i = 0
            while (i < a.size) {
                if (a[i] == "--data") data = Path.of(a[++i])
                i++
            }
            runDebugCreate(data)
        }
        "debug-circuit" -> {
            var data = Path.of("data")
            val a = args.drop(1)
            var i = 0
            while (i < a.size) {
                if (a[i] == "--data") data = Path.of(a[++i])
                i++
            }
            runDebugCircuit(data)
        }
        "debug-hsfetch" -> {
            var data = Path.of("data")
            var onion =
                "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
            var via: String? = null
            var viaIp: String? = null
            var viaOr: Int? = null
            var viaFp: String? = null
            val a = args.drop(1)
            var i = 0
            while (i < a.size) {
                when (a[i]) {
                    "--data" -> data = Path.of(a[++i])
                    "--onion" -> onion = a[++i]
                    "--via" -> via = a[++i]
                    "--via-ip" -> viaIp = a[++i]
                    "--via-orport" -> viaOr = a[++i].toInt()
                    "--via-fp" -> viaFp = a[++i]
                    else -> if (a[i].endsWith(".onion")) onion = a[i]
                }
                i++
            }
            runDebugHsFetch(data, onion, via, viaIp, viaOr, viaFp)
        }
        "debug-hsconnect" -> {
            var data = Path.of("data")
            var onion =
                "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
            var port = 80
            val a = args.drop(1)
            var i = 0
            while (i < a.size) {
                when (a[i]) {
                    "--data" -> data = Path.of(a[++i])
                    "--onion" -> onion = a[++i]
                    "--port" -> port = a[++i].toInt()
                    else -> if (a[i].endsWith(".onion")) onion = a[i]
                }
                i++
            }
            runDebugHsConnect(data, onion, port)
        }
        "debug-relay" -> {
            var data = Path.of("data")
            var orPort = 19090
            val a = args.drop(1)
            var i = 0
            while (i < a.size) {
                when (a[i]) {
                    "--data" -> data = Path.of(a[++i])
                    "--orport" -> orPort = a[++i].toInt()
                }
                i++
            }
            runDebugRelay(data, orPort)
        }
        "debug-hsintro" -> {
            var data = Path.of("data")
            val a = args.drop(1)
            var i = 0
            while (i < a.size) {
                if (a[i] == "--data") data = Path.of(a[++i])
                i++
            }
            runDebugHsIntro(data)
        }
        "debug-hshost" -> {
            var data = Path.of("data")
            var backend = 18080
            val a = args.drop(1)
            var i = 0
            while (i < a.size) {
                when (a[i]) {
                    "--data" -> data = Path.of(a[++i])
                    "--backend-port" -> backend = a[++i].toInt()
                }
                i++
            }
            runDebugHsHost(data, backend)
        }
        "version" -> println("kotlin-tor 0.1.0")
        "keygen", "--keygen" -> runKeygen(args.drop(1))
        "help", "-h", "--help" -> printHelp()
        else -> {
            System.err.println("unknown command: $cmd")
            printHelp()
            exitProcess(2)
        }
    }
}

private fun printHelp() {
    println(
        """
        kotlin-tor — pure Kotlin Tor engine (third engine beside C Tor / Arti)

        Usage:
          kotlin-tor daemon [-f torrc] [--data DIR]
          kotlin-tor bootstrap [--data DIR] [--circuit]
          kotlin-tor debug-hsfetch [--data DIR] [--onion ADDR]
          kotlin-tor debug-hsconnect [--data DIR] [--onion ADDR] [--port N]
          kotlin-tor debug-relay [--data DIR] [--orport N]
          kotlin-tor debug-hsintro [--data DIR]
          kotlin-tor debug-hshost [--data DIR] [--backend-port N]
          kotlin-tor keygen [--data DIR]
          kotlin-tor version

        bootstrap fetches consensus+descriptors (directory milestone).
        Pass --circuit to also build a 3-hop circuit.
        keygen writes Offline ed25519 master + RSA identity under DataDirectory/keys.
        debug-hsfetch downloads a v3 onion descriptor via BEGIN_DIR.
        debug-hsconnect completes INTRODUCE/RENDEZVOUS and GETs the onion.
        debug-relay runs a local TLS ORPort and builds a 3-hop through it.
        debug-hsintro ESTABLISH_INTRO + descriptor publish for a local HS.
        debug-hshost long-running HS (INTRODUCE2/RENDEZVOUS1) + local HTTP backend.
        """.trimIndent(),
    )
}

private fun runKeygen(args: List<String>) {
    var data = Path.of("data")
    var i = 0
    while (i < args.size) {
        if (args[i] == "--data") data = Path.of(args[++i])
        i++
    }
    val keys = data.resolve("keys")
    Files.createDirectories(keys)
    val material = org.kotlintor.link.OrCertMaterial.loadOrGenerate(keys)
    val ed = org.kotlintor.crypto.Ed25519Keys.generate()
    Files.write(keys.resolve("ed25519_master_id_secret_key"), ed.privateKey)
    Files.write(keys.resolve("ed25519_master_id_public_key"), ed.publicKey)
    println("Wrote OfflineMasterKey material under $keys")
    println("RSA fingerprint=${material.identityFingerprint.joinToString("") { "%02X".format(it) }}")
    println("Ed25519 id=${ed.publicKey.joinToString("") { "%02x".format(it) }}")
}

private fun loadConfig(args: List<String>): TorConfig {
    var torrc: Path? = null
    var data = Path.of("data")
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "-f", "--torrc", "--config" -> torrc = Path.of(args[++i])
            "--data" -> data = Path.of(args[++i])
        }
        i++
    }
    Files.createDirectories(data)
    return if (torrc != null && Files.exists(torrc)) {
        TorrcParser.parse(Files.readString(torrc), data)
    } else {
        TorConfig(dataDirectory = data)
    }
}

private suspend fun runBootstrap(args: List<String>) {
    val wantCircuit = "--circuit" in args
    val config = loadConfig(args)
    val daemon = TorDaemon(config)
    try {
        daemon.start(buildCircuit = wantCircuit)
        println(daemon.client.bootstrapTracker.statusLine)
        val c = daemon.client.consensusOrNull()
        if (c != null) {
            println("valid-after=${c.validAfter} valid-until=${c.validUntil} relays=${c.relays.size}")
        }
        println("circuit=${daemon.client.hasCircuit}")
    } finally {
        daemon.stop()
    }
}

private suspend fun runDaemon(args: List<String>) {
    val config = loadConfig(args)
    val daemon = TorDaemon(config)
    val control = ControlServer(daemon, daemon.scope)
    daemon.start(buildCircuit = true)
    val socksOptimistic = config.optimisticData
    var udpGw: UdpTorGatewayServer? = null
    val udpGwEndpoint = config.udpTorGatewayPort?.let { spec ->
        val gw = UdpTorGatewayServer(daemon.scope)
        gw.start(spec)
        udpGw = gw
        println("UdpTorGatewayPort ${gw.boundPort()}")
        "127.0.0.1" to gw.boundPort()
    }
    val socks = Socks5Server(
        daemon.client,
        daemon.scope,
        optimisticData = socksOptimistic,
        udpTorGateway = udpGwEndpoint,
        clientPolicy = config.socksClientPolicy(),
    )
    socks.start(config.socksPorts.first())
    control.start(config.controlPorts.first())
    var dns: DnsPortServer? = null
    config.dnsPort?.let { spec ->
        val d = DnsPortServer(daemon.client, daemon.scope)
        d.start(spec)
        dns = d
        println("DNSPort ${d.boundPort()}")
    }
    var trans: TransparentProxy? = null
    config.transPort?.let { spec ->
        val t = TransparentProxy(daemon.client, daemon.scope)
        t.start(spec)
        trans = t
        println("TransPort ${t.boundPort()}")
    }
    println("SocksPort ${socks.boundPort()}")
    println("ControlPort ${control.boundPort()}")
    println(daemon.client.bootstrapTracker.statusLine)
    Runtime.getRuntime().addShutdownHook(
        Thread {
            dns?.stop()
            trans?.stop()
            udpGw?.stop()
            socks.stop()
            control.stop()
            daemon.stop()
        },
    )
    kotlinx.coroutines.delay(Long.MAX_VALUE)
}
