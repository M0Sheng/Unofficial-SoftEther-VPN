package kittoku.mvc.control

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

data class DiagnosticEvent(
    val timestamp: Long,
    val level: String,
    val tag: String,
    val message: String,
    val sessionId: String,
) {
    fun format(): String {
        val time = timestampFormat.format(Instant.ofEpochMilli(timestamp).atZone(ZoneId.systemDefault()))
        return "[$time] [$level] [$tag]${if (sessionId.isEmpty()) "" else " [session=$sessionId]"} $message"
    }

    private companion object {
        val timestampFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS", Locale.ROOT)
    }
}

/** Stores only redacted events for display and manual export. */
internal class DiagnosticBuffer(
    private val maxEvents: Int = 1200,
    private val maxCharacters: Int = 1024 * 1024,
    private val maxMessageCharacters: Int = 64 * 1024,
) {
    private val events = ArrayDeque<DiagnosticEvent>()
    private val knownSecrets = LinkedHashSet<String>()
    private var redactionSecrets = emptyList<String>()
    private var characters = 0

    init {
        require(maxEvents > 0 && maxCharacters > 0 && maxMessageCharacters > 0)
    }

    @Synchronized fun registerSecret(value: String) {
        // No protocol payload is ever logged. This additionally catches accidental
        // inclusion of ordinary credential strings in exception messages.
        if (value.length !in 3..4096) return
        if (knownSecrets.size >= 64) knownSecrets.remove(knownSecrets.first())
        knownSecrets.add(value)
        redactionSecrets = knownSecrets.sortedByDescending { it.length }
    }

    @Synchronized fun sanitize(value: String): String {
        var safe = value.replace(CONTROLS, "")
        safe = safe.replace(AUTHORIZATION) { "${it.groupValues[1]}[REDACTED]" }
        safe = safe.replace(ASSIGNMENT) { "${it.groupValues[1]}[REDACTED]" }
        safe = safe.replace(URL_CREDENTIALS, "$1[REDACTED]@")
        safe = safe.replace(BEARER, "Bearer [REDACTED]")
        redactionSecrets.forEach { secret ->
            safe = safe.replace(secret, "[REDACTED]")
        }
        return if (safe.length <= maxMessageCharacters) safe
        else safe.take(maxMessageCharacters) + "\n[message truncated at $maxMessageCharacters characters]"
    }

    @Synchronized fun append(event: DiagnosticEvent): DiagnosticEvent {
        val safe = event.copy(level = normalizeLevel(event.level), tag = sanitize(event.tag).take(48),
            message = sanitize(event.message), sessionId = sanitize(event.sessionId).take(64))
        events.addLast(safe)
        characters += size(safe)
        trim()
        return safe
    }

    @Synchronized fun snapshot(): List<DiagnosticEvent> = events.toList()
    @Synchronized fun clear() {
        events.clear()
        characters = 0
    }

    private fun trim() {
        while (events.size > maxEvents || characters > maxCharacters) {
            characters -= size(events.removeFirst())
        }
    }

    private fun size(event: DiagnosticEvent) = event.message.length + event.tag.length + event.sessionId.length + 64

    private companion object {
        val CONTROLS = Regex("[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f\\u202a-\\u202e\\u2066-\\u2069]")
        val AUTHORIZATION = Regex("(?im)((?:proxy-)?authorization\\s*:\\s*)[^\\r\\n]+")
        val ASSIGNMENT = Regex("(?i)([\\\"']?(?:password|passwd|pwd|psk|token|access_token|refresh_token|secret|secure_password|client_key|server_key)[\\\"']?\\s*[:=]\\s*)(?:\\\"[^\\\"]*\\\"|'[^']*'|[^\\s,;}&]+)")
        val URL_CREDENTIALS = Regex("(://)[^\\s/@]+(?::[^\\s/@]*)?@")
        val BEARER = Regex("(?i)\\bBearer\\s+[^\\s,;]+")
        fun normalizeLevel(value: String) = when (val level = value.uppercase(Locale.ROOT)) {
            "DEBUG", "WARN", "ERROR" -> level
            else -> "INFO"
        }
    }
}
