package kittoku.mvc.control

import kittoku.mvc.nativecore.NativeCoreRunner
import kittoku.mvc.nativecore.traceProvisioningCommand
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticLogTest {
    @After fun resetCapture() {
        DiagnosticLog.setCollectionEnabled(false)
        DiagnosticLog.clear()
    }

    @Test fun captureRequiresOptInAndPausesWithoutDiscardingRecordedEvents() {
        assertFalse(DiagnosticLog.isCollectionEnabled())
        DiagnosticLog.record("INFO", "TEST", "before enabling")
        assertTrue(DiagnosticLog.snapshot().isEmpty())

        DiagnosticLog.setCollectionEnabled(true)
        DiagnosticLog.record("INFO", "TEST", "during capture")
        DiagnosticLog.setCollectionEnabled(false)
        DiagnosticLog.record("INFO", "TEST", "after disabling")

        assertEquals(listOf("during capture"), DiagnosticLog.snapshot().map { it.message })
    }

    @Test fun credentialsRegisteredWhileOffAreRedactedWhenCaptureStartsMidSession() {
        DiagnosticLog.redactCredentials("diagnostic-test-user", "diagnostic-test-secret")
        DiagnosticLog.setCollectionEnabled(true)
        DiagnosticLog.record("WARN", "TEST", "Authentication for diagnostic-test-user used diagnostic-test-secret")

        assertEquals("Authentication for [REDACTED] used [REDACTED]", DiagnosticLog.snapshot().single().message)
    }

    @Test fun provisioningTraceOmitsCommandOutputAndExceptionMessages() {
        DiagnosticLog.setCollectionEnabled(true)
        val result = traceProvisioningCommand("TUN", "test", "AccountPasswordSet") {
            NativeCoreRunner.CommandResult(7, "synthetic encoded credential")
        }
        val error = IllegalArgumentException("synthetic password in exception")
        val attempt = runCatching {
            traceProvisioningCommand("TAP", "test", "AccountPasswordSet") { throw error }
        }

        assertEquals(7, result.exitCode)
        assertEquals(error, attempt.exceptionOrNull())
        val events = DiagnosticLog.snapshot()
        assertEquals(listOf("WARN", "WARN"), events.map { it.level })
        assertTrue(events[0].message.startsWith("mode=TUN command=AccountPasswordSet exit=7 "))
        assertTrue(events[1].message.startsWith("mode=TAP command=AccountPasswordSet exception=IllegalArgumentException "))
        assertFalse(events.any { it.message.contains("synthetic") })
    }
}
