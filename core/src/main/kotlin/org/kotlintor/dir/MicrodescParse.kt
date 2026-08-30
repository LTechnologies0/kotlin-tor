package org.kotlintor.dir

/**
 * Microdescriptor parse (C Tor `microdesc_parse.c`).
 *
 * Inventory: `L1:feature/dirparse/microdesc_parse.c`
 */
object MicrodescParse {
    fun parseFamily(document: String): Set<String> = DescriptorParser.parseFamily(document)
    fun parseNtorOnionKey(document: String) = DescriptorParser.parseNtorOnionKey(document)
}
