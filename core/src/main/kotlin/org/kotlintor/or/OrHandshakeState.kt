package org.kotlintor.or

/** C Tor `or_handshake_state_t`. */
data class OrHandshakeState(
    var receivedVersions: Boolean = false,
    var receivedCerts: Boolean = false,
    var receivedAuthChallenge: Boolean = false,
    var receivedNetinfo: Boolean = false,
    var startedHere: Boolean = true,
)
