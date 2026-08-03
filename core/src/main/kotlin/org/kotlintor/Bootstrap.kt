package org.kotlintor

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class BootstrapPhase(val tag: String, val progress: Int) {
    STARTING("NOTICE BOOTSTRAP PROGRESS=0 TAG=starting SUMMARY=\"Starting\"", 0),
    CONN_DIR("NOTICE BOOTSTRAP PROGRESS=5 TAG=conn_dir SUMMARY=\"Connecting to directory server\"", 5),
    HANDSHAKE_DIR("NOTICE BOOTSTRAP PROGRESS=10 TAG=handshake_dir SUMMARY=\"Finishing handshake with directory server\"", 10),
    REQUESTING_STATUS("NOTICE BOOTSTRAP PROGRESS=15 TAG=requesting_status SUMMARY=\"Fetching consensus\"", 15),
    LOADING_STATUS("NOTICE BOOTSTRAP PROGRESS=20 TAG=loading_status SUMMARY=\"Loading consensus\"", 20),
    LOADING_KEYS("NOTICE BOOTSTRAP PROGRESS=40 TAG=loading_keys SUMMARY=\"Loading authority certificates\"", 40),
    REQUESTING_DESCRIPTORS("NOTICE BOOTSTRAP PROGRESS=45 TAG=requesting_descriptors SUMMARY=\"Fetching microdescriptors\"", 45),
    LOADING_DESCRIPTORS("NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors SUMMARY=\"Loading microdescriptors\"", 50),
    CONN_OR("NOTICE BOOTSTRAP PROGRESS=80 TAG=conn_or SUMMARY=\"Connecting to the Tor network\"", 80),
    HANDSHAKE_OR("NOTICE BOOTSTRAP PROGRESS=85 TAG=handshake_or SUMMARY=\"Finishing handshake with first hop\"", 85),
    CIRCUIT_CREATE("NOTICE BOOTSTRAP PROGRESS=90 TAG=circuit_create SUMMARY=\"Establishing a Tor circuit\"", 90),
    DONE("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"", 100),
}

class BootstrapTracker {
    private val _phase = MutableStateFlow(BootstrapPhase.STARTING)
    val phase: StateFlow<BootstrapPhase> = _phase.asStateFlow()

    fun advance(to: BootstrapPhase) {
        if (to.progress >= _phase.value.progress) {
            _phase.value = to
        }
    }

    val statusLine: String get() = _phase.value.tag
}
