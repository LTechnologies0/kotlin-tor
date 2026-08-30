package org.kotlintor.dir

/**
 * Directory document tokenization (C Tor `parsecommon.c`).
 *
 * Inventory: `L1:feature/dirparse/parsecommon.c`
 *
 * Implementation: [DirParseCommon].
 */
object ParseCommon {
    fun keywordMap(document: String) = DirParseCommon.keywordMap(document)
    fun keywordAll(document: String, key: String) = DirParseCommon.keywordAll(document, key)
    fun requireKeyword(document: String, key: String) = DirParseCommon.requireKeyword(document, key)
    fun hasKeyword(document: String, key: String) = DirParseCommon.hasKeyword(document, key)
}
