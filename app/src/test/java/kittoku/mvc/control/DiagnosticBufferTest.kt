package kittoku.mvc.control

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread

class DiagnosticBufferTest {
    private fun event(message: String, time: Long = 1) = DiagnosticEvent(time, "INFO", "TLS", message, "session-a")

    @Test fun ringKeepsNewestEventsWithoutChangingSnapshots() {
        val buffer = DiagnosticBuffer(maxEvents = 3)
        buffer.append(event("one"))
        val original = buffer.snapshot()
        listOf("two", "three", "four").forEach { buffer.append(event(it)) }
        assertEquals(listOf("two", "three", "four"), buffer.snapshot().map { it.message })
        assertEquals(listOf("one"), original.map { it.message })
    }

    @Test fun characterBudgetBoundsLargeMessages() {
        val buffer = DiagnosticBuffer(maxEvents = 20, maxCharacters = 512, maxMessageCharacters = 80)
        repeat(20) { buffer.append(event("x".repeat(400))) }
        val snapshot = buffer.snapshot()
        assertTrue(snapshot.size in 1..3)
        assertTrue(snapshot.all { it.message.contains("truncated") && it.message.length < 150 })
    }

    @Test fun authorizationHeadersAndBearerTokensAreRemoved() {
        val buffer = DiagnosticBuffer()
        val redacted = buffer.append(event("Authorization: Basic dXNlcjpwYXNz\nProxy-Authorization: Bearer sensitive-token\nnext Bearer abc123")).message
        assertFalse(redacted.contains("dXNlcjpwYXNz"))
        assertFalse(redacted.contains("sensitive-token"))
        assertFalse(redacted.contains("abc123"))
        assertTrue(redacted.contains("Proxy-Authorization"))
    }

    @Test fun assignmentsAndJsonSecretsAreRemovedWithoutRemovingNetworkMetadata() {
        val buffer = DiagnosticBuffer()
        val original = "password=hello pwd:there psk='wifi key' token=aaa&host=vpn.example \"password\":\"secret space\" secure_password=deadbeef"
        val safe = buffer.append(event(original)).message
        listOf("hello", "there", "wifi key", "aaa", "secret space", "deadbeef").forEach { assertFalse("Leaked $it: $safe", safe.contains(it)) }
        assertTrue(safe.contains("host=vpn.example"))
    }

    @Test fun registeredCredentialsAreRemovedFromExceptionMessagesAndAllFields() {
        val buffer = DiagnosticBuffer()
        buffer.registerSecret("hunter2")
        buffer.registerSecret("alice-user")
        val safe = buffer.append(DiagnosticEvent(1, "error", "alice-user", "Exception: hunter2 for alice-user", "hunter2"))
        assertFalse(safe.toString().contains("hunter2"))
        assertFalse(safe.toString().contains("alice-user"))
        assertEquals("ERROR", safe.level)
    }

    @Test fun urlUserInformationIsRemoved() {
        val safe = DiagnosticBuffer().append(event("https://alice:password123@vpn.example:443/path")).message
        assertEquals("https://[REDACTED]@vpn.example:443/path", safe)
    }

    @Test fun readableMultilineExceptionsKeepStackAndStripTerminalAndBidiControls() {
        val message = "Exception\n\tat x.y\nCaused by: name\u0000\u001b\u202e"
        val safe = DiagnosticBuffer().append(event(message)).message
        assertEquals("Exception\n\tat x.y\nCaused by: name", safe)
    }

    @Test fun clearRemovesPreviousHistoryAndNewEventsCanBeAdded() {
        val buffer = DiagnosticBuffer()
        buffer.append(event("old")); buffer.clear()
        assertTrue(buffer.snapshot().isEmpty())
        buffer.append(event("new"))
        assertEquals("new", buffer.snapshot().single().message)
    }

    @Test fun concurrentAppendsAndSnapshotsStayBoundedAndComplete() {
        val buffer = DiagnosticBuffer(maxEvents = 80)
        val start = CountDownLatch(1)
        val workers = (0 until 6).map { worker -> thread {
            start.await()
            repeat(200) { n ->
                buffer.append(event("worker=$worker n=$n"))
                assertTrue(buffer.snapshot().size <= 80)
            }
        } }
        start.countDown(); workers.forEach { it.join() }
        assertEquals(80, buffer.snapshot().size)
        assertEquals(80, buffer.snapshot().map { it.message }.distinct().size)
    }

    @Test fun formatterIncludesTimeLevelStageSessionAndExceptionBody() {
        val formatted = event("failure\nCaused by: invalid certificate").format()
        assertTrue(formatted.contains("[INFO] [TLS] [session=session-a]"))
        assertTrue(formatted.endsWith("failure\nCaused by: invalid certificate"))
    }
}
