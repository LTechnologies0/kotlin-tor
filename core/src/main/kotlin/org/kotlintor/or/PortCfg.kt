package org.kotlintor.or

import org.kotlintor.config.ListenSpec

/** C Tor `entry_port_cfg_t` / `port_cfg_t` / `server_port_cfg_t`. */
data class PortCfg(
    val listen: ListenSpec,
    val isolationFlags: Int = 0,
    val sessionGroup: Int = 0,
    val isServer: Boolean = false,
)

typealias EntryPortCfg = PortCfg
typealias ServerPortCfg = PortCfg
