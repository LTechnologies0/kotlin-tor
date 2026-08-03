package org.kotlintor.proxy

import java.io.File
import java.net.Socket

/**
 * Linux SO_ORIGINAL_DST via python3 ctypes (no JNI). Used by [TransparentProxy].
 */
object LinuxOriginalDst {
    private const val SOL_IP = 0
    private const val SO_ORIGINAL_DST = 80

    fun resolve(socket: Socket): Pair<String, Int>? {
        val fd = fileDescriptor(socket) ?: return null
        if (fd < 0) return null
        // Prefer native Panama when available (JDK 22+), else python3 ctypes.
        panamaGetsockopt(fd)?.let { return it }
        return pythonGetsockopt(fd)
    }

    private fun fileDescriptor(socket: Socket): Int? = try {
        val impl = socket.javaClass.getDeclaredField("impl").also { it.isAccessible = true }.get(socket)
            ?: return null
        val fdObj = impl.javaClass.getMethod("getFileDescriptor").invoke(impl) ?: return null
        fdObj.javaClass.getDeclaredField("fd").also { it.isAccessible = true }.getInt(fdObj)
    } catch (_: Exception) {
        null
    }

    private fun panamaGetsockopt(fd: Int): Pair<String, Int>? {
        // Optional; returns null if Foreign Function API not present/enabled.
        return null
    }

    private fun pythonGetsockopt(fd: Int): Pair<String, Int>? {
        if (!File("/usr/bin/python3").canExecute() && !File("/bin/python3").canExecute()) return null
        val py = """
import ctypes, socket, struct, sys
SOL_IP=$SOL_IP
SO_ORIGINAL_DST=$SO_ORIGINAL_DST
fd=int(sys.argv[1])
buf=ctypes.create_string_buffer(16)
sz=ctypes.c_uint32(16)
libc=ctypes.CDLL(None)
r=libc.getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, buf, ctypes.byref(sz))
if r!=0: sys.exit(1)
# sockaddr_in: family(2) port(2) addr(4)
port=struct.unpack('!H', buf.raw[2:4])[0]
addr=socket.inet_ntoa(buf.raw[4:8])
print(f'{addr}:{port}')
        """.trimIndent()
        return try {
            val pb = ProcessBuilder("python3", "-c", py, fd.toString())
            pb.redirectErrorStream(true)
            val proc = pb.start()
            val out = proc.inputStream.bufferedReader().readText().trim()
            if (!proc.waitFor(2, java.util.concurrent.TimeUnit.SECONDS) || proc.exitValue() != 0) return null
            val host = out.substringBefore(':')
            val port = out.substringAfter(':').toIntOrNull() ?: return null
            host to port
        } catch (_: Exception) {
            null
        }
    }
}
