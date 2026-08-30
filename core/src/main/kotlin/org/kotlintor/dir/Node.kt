package org.kotlintor.dir

/**
 * Nodelist node mirror (C Tor `node_t`).
 *
 * Inventory: `L2:core/or/node_t`, `L2:feature/nodelist/node_t`
 *
 * Runtime selection uses [RouterStatus] / [RouterList]; this names the C Tor node handle.
 */
data class Node(
    val identityHex: String,
    val nickname: String = "",
    val isRunning: Boolean = false,
    val isValid: Boolean = true,
    val isGuard: Boolean = false,
    val isExit: Boolean = false,
    val isHsDir: Boolean = false,
    val family: NodeFamily? = null,
) {
    companion object {
        fun fromRouterStatus(rs: RouterStatus, family: NodeFamily? = null): Node =
            Node(
                identityHex = rs.fingerprintHex,
                nickname = rs.nickname,
                isRunning = rs.isRunning,
                isValid = "Valid" in rs.flags || rs.flags.isEmpty(),
                isGuard = rs.isGuard,
                isExit = rs.isExit,
                isHsDir = rs.isHsDir,
                family = family,
            )
    }
}
