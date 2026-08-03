package org.kotlintor.dir

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URI
import java.nio.charset.StandardCharsets

/**
 * POST a server / bridge descriptor to directory authorities (dir-spec publish).
 * Authorities may reject unsigned / incomplete descriptors; we still attempt upload.
 */
class DescriptorPublisher(
    private val authorities: List<DirectoryAuthority> = DefaultAuthorities.ALL,
) {
    data class Result(val authority: String, val code: Int, val body: String)

    suspend fun publishServerDescriptor(document: String): List<Result> = withContext(Dispatchers.IO) {
        val results = mutableListOf<Result>()
        for (auth in authorities) {
            val url = "http://${auth.address}:${auth.dirPort}/tor/"
            try {
                val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    connectTimeout = 15_000
                    readTimeout = 30_000
                    setRequestProperty("Content-Type", "text/plain")
                    setRequestProperty("User-Agent", "kotlin-tor/0.1")
                }
                conn.outputStream.use { it.write(document.toByteArray(StandardCharsets.UTF_8)) }
                val code = conn.responseCode
                val body = runCatching {
                    (if (code in 200..299) conn.inputStream else conn.errorStream)
                        ?.readBytes()?.toString(StandardCharsets.UTF_8).orEmpty()
                }.getOrDefault("")
                results += Result("${auth.address}:${auth.dirPort}", code, body.take(200))
            } catch (e: Exception) {
                results += Result("${auth.address}:${auth.dirPort}", -1, e.message ?: "error")
            }
        }
        results
    }
}
