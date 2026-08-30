package org.kotlintor.dir

object DirParseCommon {
    /** Split a dir-spec document into keyword → multi-line value map (first wins). */
    fun keywordMap(document: String): Map<String, String> {
        val out = linkedMapOf<String, String>()
        val lines = document.replace("\r\n", "\n").split('\n')
        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            if (line.isEmpty() || line.startsWith("-----BEGIN")) {
                i++
                continue
            }
            val sp = line.indexOf(' ')
            val key = if (sp < 0) line else line.substring(0, sp)
            val rest = if (sp < 0) "" else line.substring(sp + 1)
            if (key !in out) out[key] = rest
            i++
        }
        return out
    }

    /** All values for a repeated keyword (C Tor tokenize multi). */
    fun keywordAll(document: String, key: String): List<String> {
        val out = ArrayList<String>()
        for (line in document.replace("\r\n", "\n").lineSequence()) {
            if (line.startsWith("$key ")) out += line.removePrefix("$key ").trim()
            else if (line == key) out += ""
        }
        return out
    }

    fun requireKeyword(document: String, key: String): String =
        keywordMap(document)[key] ?: error("missing keyword $key")

    fun hasKeyword(document: String, key: String): Boolean = key in keywordMap(document)
}

