package org.kotlintor.net

import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

/** Bidirectional copy until either side EOF/closes. */
object StreamRelay {
    suspend fun splice(
        a: BytePipe,
        b: BytePipe,
        bufSize: Int = 16 * 1024,
        onChunkAtoB: ((Int) -> Unit)? = null,
        onChunkBtoA: ((Int) -> Unit)? = null,
    ) {
        coroutineScope {
            val up = launch {
                copyOneWay(a, b, bufSize, onChunkAtoB)
                runCatching { b.close() }
            }
            try {
                copyOneWay(b, a, bufSize, onChunkBtoA)
            } finally {
                up.cancel()
                runCatching { a.close() }
                runCatching { b.close() }
            }
        }
    }

    private suspend fun copyOneWay(
        from: BytePipe,
        to: BytePipe,
        bufSize: Int,
        onChunk: ((Int) -> Unit)?,
    ) {
        val buf = ByteArray(bufSize)
        while (true) {
            val n = from.read(buf)
            if (n < 0) break
            if (n == 0) continue
            to.write(buf, 0, n)
            onChunk?.invoke(n)
        }
    }
}
