package org.kotlintor.dir

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DirAuthQuorumTest {
    @Test
    fun `majority of three requires two`() {
        val known = setOf("aa", "bb", "cc")
        assertFalse(DirAuthQuorum.hasQuorum(listOf("aa"), known))
        assertTrue(DirAuthQuorum.hasQuorum(listOf("aa", "bb"), known))
        assertTrue(DirAuthQuorum.hasQuorum(listOf("aa", "bb", "cc", "aa"), known))
        assertFalse(DirAuthQuorum.hasQuorum(listOf("aa", "zz"), known))
    }
}
