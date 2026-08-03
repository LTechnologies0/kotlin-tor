package org.kotlintor.proxy

import kotlinx.coroutines.sync.Semaphore

/**
 * Shared accept / in-flight limits for proxy listeners (DoS mitigation).
 */
object ProxyAcceptLimits {
    const val DEFAULT_TCP = 256
    const val DEFAULT_DNS = 128
    const val DEFAULT_CONTROL = 32

    fun semaphore(max: Int): Semaphore = Semaphore(max.coerceAtLeast(1))
}
