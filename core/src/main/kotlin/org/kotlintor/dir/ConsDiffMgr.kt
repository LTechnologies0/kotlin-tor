package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Consensus-diff manager (C Tor `consdiffmgr.c`) — store diffs by from→to hash,
 * optionally persist under [storeDir].

 * Inventory: `L1:feature/dircache/consdiffmgr.c`
 */
class ConsDiffMgr(
    private val cache: ConsCache = ConsCache(),
    private val storeDir: java.nio.file.Path? = null,
) {
    private val diffs = ConcurrentHashMap<String, String>() // "oldHex:newHex" → diff body

    init {
        storeDir?.let { loadFromDisk(it) }
    }

    fun rememberConsensus(body: String): ConsCache.Entry = cache.put(body)

    fun storeDiff(oldBody: String, newBody: String): String {
        val diff = ConsDiff.generate(oldBody, newBody)
        val oldH = ConsDiff.sha3Hex(oldBody)
        val newH = ConsDiff.sha3Hex(newBody)
        val key = "$oldH:$newH"
        diffs[key] = diff
        cache.put(newBody)
        storeDir?.let { dir ->
            runCatching {
                java.nio.file.Files.createDirectories(dir)
                java.nio.file.Files.writeString(dir.resolve("$oldH-$newH.diff"), diff)
            }
        }
        return diff
    }

    fun findDiff(oldSha3Hex: String, newSha3Hex: String): String? =
        diffs["${oldSha3Hex.lowercase()}:${newSha3Hex.lowercase()}"]

    fun applyCached(oldBody: String, newSha3Hex: String): String? {
        val oldH = ConsDiff.sha3Hex(oldBody)
        val diff = findDiff(oldH, newSha3Hex) ?: return null
        return ConsDiff.apply(oldBody, diff)
    }

    fun size(): Int = diffs.size

    fun loadFromDisk(dir: java.nio.file.Path) {
        if (!java.nio.file.Files.isDirectory(dir)) return
        java.nio.file.Files.list(dir).use { stream ->
            stream.filter { it.fileName.toString().endsWith(".diff") }.forEach { path ->
                val name = path.fileName.toString().removeSuffix(".diff")
                val parts = name.split('-', limit = 2)
                if (parts.size == 2 && parts[0].length == 64 && parts[1].length == 64) {
                    val body = runCatching { java.nio.file.Files.readString(path) }.getOrNull() ?: return@forEach
                    diffs["${parts[0]}:${parts[1]}"] = body
                }
            }
        }
    }
}
