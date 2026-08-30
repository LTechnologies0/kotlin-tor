package org.kotlintor.or

/** C Tor `networkstatus_voter_info_t`. */
data class NetworkstatusVoterInfo(
    val nickname: String,
    val identityHex: String,
    val address: String,
    val dirPort: Int,
    val orPort: Int,
)
