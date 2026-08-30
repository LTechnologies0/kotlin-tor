package org.kotlintor.config

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Persistent OR state file (C Tor `statefile.c` / `or_state_t`).
 *
 * Inventory: `L1:app/config/statefile.c`
 */
object Statefile {
    private val loaded = AtomicBoolean(false)
    private val dirty = AtomicBoolean(false)
    private val values = ConcurrentHashMap<String, String>()
    private var path: Path? = null

    fun reset() {
        loaded.set(false)
        dirty.set(false)
        values.clear()
        path = null
    }

    fun isLoaded(): Boolean = loaded.get()

    fun isDirty(): Boolean = dirty.get()

    fun markDirty() {
        dirty.set(true)
    }

    fun get(key: String): String? = values[key]

    fun set(key: String, value: String) {
        values[key] = value
        dirty.set(true)
    }

    /** C Tor `or_state_load` — parse simple Key Value lines. */
    fun load(statePath: Path): Int {
        path = statePath
        values.clear()
        if (!Files.exists(statePath)) {
            loaded.set(true)
            dirty.set(false)
            return 0
        }
        Files.readAllLines(statePath).forEach { line ->
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) return@forEach
            val sp = t.indexOf(' ')
            if (sp > 0) values[t.substring(0, sp)] = t.substring(sp + 1).trim()
            else values[t] = ""
        }
        loaded.set(true)
        dirty.set(false)
        return 0
    }

    /** C Tor `or_state_save`. */
    fun save(nowSec: Long = System.currentTimeMillis() / 1000): Int {
        val p = path ?: return -1
        if (!dirty.get() && Files.exists(p)) return 0
        values["LastWritten"] = nowSec.toString()
        val body = values.entries.sortedBy { it.key }.joinToString("\n") { "${it.key} ${it.value}" } + "\n"
        Files.createDirectories(p.parent)
        Files.writeString(p, body)
        dirty.set(false)
        return 0
    }

    fun freeAll() = reset()
}
