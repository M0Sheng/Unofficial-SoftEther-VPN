package kittoku.mvc.control

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.util.Locale

data class TrafficSnapshot(val received: Long, val sent: Long, val receiveRate: Double, val sendRate: Double, val available: Boolean = true) {
    fun notificationText(): String =
        if (available) "↓ ${format(receiveRate)}/s  ↑ ${format(sendRate)}/s"
        else appText(R.string.network_runtime_notification_traffic_pending_data)

    fun totalsText(): String =
        if (available) {
            appText(R.string.network_runtime_notification_traffic_totals, format(received.toDouble()), format(sent.toDouble()))
        } else appText(R.string.network_runtime_notification_traffic_totals_pending)

    private fun format(bytes: Double): String = when {
        bytes >= 1024.0 * 1024 * 1024 -> String.format(Locale.ROOT, "%.2f GiB", bytes / (1024.0 * 1024 * 1024))
        bytes >= 1024.0 * 1024 -> String.format(Locale.ROOT, "%.1f MiB", bytes / (1024.0 * 1024))
        bytes >= 1024 -> String.format(Locale.ROOT, "%.1f KiB", bytes / 1024)
        else -> String.format(Locale.ROOT, "%.0f B", bytes)
    }
}

/** Counts tunnel application bytes, including protocol framing, rather than all device traffic. */
internal class TrafficCounter {
    private var session = ""
    private var received = 0L
    private var sent = 0L
    private var previousReceived = 0L
    private var previousSent = 0L
    private var sampledAt = 0L
    private var receiveRate = 0.0
    private var sendRate = 0.0
    private var available = true

    @Synchronized fun reset(nowMillis: Long) {
        session = ""; received = 0; sent = 0; previousReceived = 0; previousSent = 0
        sampledAt = nowMillis; receiveRate = 0.0; sendRate = 0.0
        available = true
    }
    @Synchronized fun useSession(id: String, available: Boolean = true) { session = id; this.available = available }
    @Synchronized fun markAvailable(id: String) { if (id.isNotEmpty() && id == session) available = true }
    @Synchronized fun received(id: String, bytes: Long) {
        if (session.isNotEmpty() && session == id && bytes > 0) received = plus(received, bytes)
    }
    @Synchronized fun sent(id: String, bytes: Long) {
        if (session.isNotEmpty() && session == id && bytes > 0) sent = plus(sent, bytes)
    }
    @Synchronized fun sample(nowMillis: Long): TrafficSnapshot {
        val elapsed = nowMillis - sampledAt
        if (elapsed >= 500) {
            receiveRate = (received - previousReceived) * 1000.0 / elapsed
            sendRate = (sent - previousSent) * 1000.0 / elapsed
            previousReceived = received; previousSent = sent; sampledAt = nowMillis
        } else if (elapsed < 0) {
            sampledAt = nowMillis; previousReceived = received; previousSent = sent
            receiveRate = 0.0; sendRate = 0.0
        }
        return TrafficSnapshot(received, sent, receiveRate, sendRate, available)
    }
    private fun plus(total: Long, value: Long) = if (Long.MAX_VALUE - total < value) Long.MAX_VALUE else total + value
}

object TrafficMeter {
    private val counter = TrafficCounter()
    private fun now() = System.nanoTime() / 1_000_000
    fun reset() = counter.reset(now())
    fun useSession(id: String, available: Boolean = true) = counter.useSession(id, available)
    fun markAvailable(id: String) = counter.markAvailable(id)
    fun received(id: String, bytes: Long) = counter.received(id, bytes)
    fun sent(id: String, bytes: Long) = counter.sent(id, bytes)
    fun snapshot() = counter.sample(now())
}
