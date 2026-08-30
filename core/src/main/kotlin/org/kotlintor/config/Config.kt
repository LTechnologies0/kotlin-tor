package org.kotlintor.config

import java.nio.file.Files
import java.nio.file.Path

/**
 * Tor configuration entry (C Tor `config.c`).
 *
 * Inventory: `L1:app/config/config.c`
 *
 * Implementation: [TorrcParser] / [TorConfig].
 */
object Config {
    fun parse(text: String, dataDir: Path = Files.createTempDirectory("ktor-cfg")): TorConfig =
        TorrcParser.parse(text, dataDir)

    fun parseSocksPort(line: String): ListenSpec = ListenSpec.parse(line)

    fun hasOption(config: TorConfig, key: String): Boolean =
        key in config.acknowledgedKeys ||
            (key.equals("SocksPort", ignoreCase = true) && config.socksPorts.isNotEmpty()) ||
            (key.equals("ControlPort", ignoreCase = true) && config.controlPorts.isNotEmpty())
}
