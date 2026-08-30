package org.kotlintor.os

import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.charset.StandardCharsets

/**
 * Linux TUN (`/dev/net/tun`) via JDK Panama FFM — no JNI .so.
 *
 * Opens a userspace TUN with IFF_TUN|IFF_NO_PI and exposes Java streams
 * for [org.kotlintor.net.stack.StreamPacketIo].
 */
class LinuxTunDevice private constructor(
    val name: String,
    private val nativeFd: Int,
    private val ownedFd: FileDescriptor,
) : AutoCloseable {
    val inputStream: InputStream = FileInputStream(ownedFd)
    val outputStream: OutputStream = FileOutputStream(ownedFd)

    val fd: Int get() = nativeFd

    override fun close() {
        // Closing either stream closes the shared FD.
        runCatching { inputStream.close() }
    }

    companion object {
        private const val O_RDWR = 2
        private const val IFF_TUN = 0x0001
        private const val IFF_NO_PI = 0x1000
        /** `_IOW('T', 202, int)` on Linux. */
        private const val TUNSETIFF = 0x400454caL
        private const val IFNAMSIZ = 16

        fun isLinux(): Boolean =
            System.getProperty("os.name", "").lowercase().contains("linux")

        fun canOpen(): Boolean {
            if (!isLinux()) return false
            return java.io.File("/dev/net/tun").exists()
        }

        /**
         * Create TUN named [preferredName] (kernel may assign `ktor%d` if taken).
         * Requires `CAP_NET_ADMIN` (typically root).
         */
        fun open(preferredName: String = "ktor0"): LinuxTunDevice {
            check(isLinux()) { "LinuxTunDevice requires Linux" }
            val openMh = openHandle() ?: error("open() symbol missing")
            val ioctlMh = ioctlHandle() ?: error("ioctl() symbol missing")
            return Arena.ofConfined().use { arena ->
                val path = allocateCString(arena, "/dev/net/tun")
                val fd = openMh.invoke(path, O_RDWR) as Int
                if (fd < 0) error("open(/dev/net/tun) failed fd=$fd (need CAP_NET_ADMIN?)")
                try {
                    val ifr = arena.allocate(40)
                    ifr.fill(0)
                    val nameBytes = preferredName.toByteArray(StandardCharsets.US_ASCII)
                        .take(IFNAMSIZ - 1)
                        .toByteArray()
                    MemorySegment.copy(
                        MemorySegment.ofArray(nameBytes),
                        0,
                        ifr,
                        0,
                        nameBytes.size.toLong(),
                    )
                    ifr.set(ValueLayout.JAVA_SHORT, 16L, (IFF_TUN or IFF_NO_PI).toShort())
                    val rc = ioctlMh.invoke(fd, TUNSETIFF, ifr) as Int
                    if (rc != 0) error("TUNSETIFF failed rc=$rc (need CAP_NET_ADMIN?)")
                    val assigned = ByteArray(IFNAMSIZ)
                    for (i in 0 until IFNAMSIZ) {
                        assigned[i] = ifr.get(ValueLayout.JAVA_BYTE, i.toLong())
                    }
                    val iface = assigned.takeWhile { it != 0.toByte() }
                        .toByteArray()
                        .toString(StandardCharsets.US_ASCII)
                        .ifBlank { preferredName }
                    LinuxTunDevice(iface, fd, fileDescriptorFromFd(fd))
                } catch (t: Throwable) {
                    closeFd(fd)
                    throw t
                }
            }
        }

        private fun allocateCString(arena: Arena, s: String): MemorySegment {
            val bytes = (s + "\u0000").toByteArray(StandardCharsets.UTF_8)
            val seg = arena.allocate(bytes.size.toLong())
            MemorySegment.copy(MemorySegment.ofArray(bytes), 0, seg, 0, bytes.size.toLong())
            return seg
        }

        private fun openHandle() =
            Linker.nativeLinker().defaultLookup().find("open").orElse(null)?.let { sym ->
                Linker.nativeLinker().downcallHandle(
                    sym,
                    FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS,
                        ValueLayout.JAVA_INT,
                    ),
                )
            }

        private fun ioctlHandle() =
            Linker.nativeLinker().defaultLookup().find("ioctl").orElse(null)?.let { sym ->
                Linker.nativeLinker().downcallHandle(
                    sym,
                    FunctionDescriptor.of(
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS,
                    ),
                )
            }

        private fun closeFd(fd: Int) {
            if (fd < 0) return
            runCatching {
                val close = Linker.nativeLinker().defaultLookup().find("close").orElse(null) ?: return
                val mh = Linker.nativeLinker().downcallHandle(
                    close,
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT),
                )
                mh.invoke(fd)
            }
        }

        private fun fileDescriptorFromFd(fd: Int): FileDescriptor {
            val jfd = FileDescriptor()
            val field = FileDescriptor::class.java.getDeclaredField("fd").also { it.isAccessible = true }
            field.setInt(jfd, fd)
            return jfd
        }
    }
}
