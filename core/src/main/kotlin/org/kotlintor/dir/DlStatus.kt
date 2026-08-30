package org.kotlintor.dir

/**
 * Directory download status (C Tor `dlstatus.c`).
 *
 * Inventory: `L1:feature/dirclient/dlstatus.c`
 *
 * Implementation: [DownloadStatus].
 */
object DlStatus {
    fun create(): DownloadStatus = DownloadStatus()
}
