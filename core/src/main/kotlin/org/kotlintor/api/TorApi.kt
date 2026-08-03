package org.kotlintor.api

import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser
import java.nio.file.Path

/**
 * Embedding API surface (C Tor `tor_api.c` / `tor_main_configuration` lite).
 *
 * Inventory: `L1:feature/api/tor_api.c`
 */
class TorApiConfiguration {
    var dataDirectory: Path? = null
    private val torrc = StringBuilder()

    fun addTorrcLine(line: String) {
        torrc.append(line.trimEnd()).append('\n')
    }

    fun buildConfig(): TorConfig {
        val dir = dataDirectory ?: Path.of(".").toAbsolutePath().normalize()
        return TorrcParser.parse(torrc.toString(), dir)
    }
}

object TorApi {
    fun newConfiguration(): TorApiConfiguration = TorApiConfiguration()

    fun version(): String = "0.1.0-SNAPSHOT"
}
