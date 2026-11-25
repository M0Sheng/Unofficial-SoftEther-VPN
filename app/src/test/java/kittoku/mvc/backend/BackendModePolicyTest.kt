package kittoku.mvc.backend

import org.junit.Assert.*
import org.junit.Test

class BackendModePolicyTest {
    private class Store(initial: String?) {
        val state = BackendMigrationState()
        var memory = initial
        var durable = initial
        val settings = mutableMapOf<String, Any>("AUTH_PASSWORD_ENCODING" to "GBK", "HOME_PASSWORD" to Any(), "HOME_USERNAME" to Any())
        val trust = mutableMapOf("trusted_endpoint" to "fixture-pin", "pending_certificate" to "fixture-request")
        val calls = mutableListOf<String>()
        var clearSucceeds = true
        var persistSucceeds = true
        fun migrate() = state.migrate(memory, clearPending = {
            calls += "clear-pending"
            trust.remove("pending_certificate")
            clearSucceeds
        }, persistNative = {
            calls += "persist-backend"
            memory = BackendModePolicy.ROOT_NATIVE
            if (persistSucceeds) durable = memory
            persistSucceeds
        })
    }

    @Test fun absentModeBecomesNativeWithoutDroppingOtherSettingsOrRememberedTrust() {
        val store = Store(null)
        val settings = store.settings.toMap()
        assertEquals("ROOT_NATIVE", store.migrate())
        assertEquals("ROOT_NATIVE", store.durable)
        assertEquals(settings, store.settings)
        assertEquals("fixture-pin", store.trust["trusted_endpoint"])
        assertFalse(store.trust.containsKey("pending_certificate"))
        assertEquals(listOf("clear-pending", "persist-backend"), store.calls)
    }

    @Test fun retiredModeInvalidatesPendingBeforePersistingNative() {
        val store = Store("ROOT_TAP")
        assertEquals("ROOT_NATIVE", store.migrate())
        assertEquals(listOf("clear-pending", "persist-backend"), store.calls)
        assertEquals("ROOT_NATIVE", store.durable)
    }

    @Test fun explicitlySelectedTunIsPreservedWithoutWritesOrApprovalChanges() {
        val store = Store("TUN")
        assertEquals("TUN", store.migrate())
        assertEquals("TUN", store.durable)
        assertTrue(store.calls.isEmpty())
        assertEquals("fixture-request", store.trust["pending_certificate"])
    }

    @Test fun nativeDoesNotDiscardAnExistingNativeApproval() {
        val store = Store("ROOT_NATIVE")
        assertEquals("ROOT_NATIVE", store.migrate())
        assertTrue(store.calls.isEmpty())
        assertEquals("fixture-request", store.trust["pending_certificate"])
    }

    @Test fun unknownAndBlankModesAreRejectedWithoutMutations() {
        for (mode in listOf("", "root_tap", "OPENVPN")) {
            val store = Store(mode)
            assertThrows(IllegalArgumentException::class.java) { store.migrate() }
            assertEquals(mode, store.memory)
            assertTrue(store.calls.isEmpty())
        }
    }

    @Test fun failedPendingInvalidationPreventsBackendWrite() {
        val store = Store("ROOT_TAP").also { it.clearSucceeds = false }
        assertThrows(IllegalStateException::class.java) { store.migrate() }
        assertEquals("ROOT_TAP", store.memory)
        assertEquals(listOf("clear-pending"), store.calls)
    }

    @Test fun pendingInvalidationCanBeRetriedWithoutPromotingTheOldCandidate() {
        val store = Store("ROOT_TAP").also { it.clearSucceeds = false }
        assertThrows(IllegalStateException::class.java) { store.migrate() }
        store.clearSucceeds = true
        assertEquals("ROOT_NATIVE", store.migrate())
        assertFalse(store.trust.containsKey("pending_certificate"))
        assertEquals(listOf("clear-pending", "clear-pending", "persist-backend"), store.calls)
    }

    @Test fun failedCommitThatChangedMemoryIsFlushedOnRetry() {
        val store = Store("ROOT_TAP").also { it.persistSucceeds = false }
        assertThrows(IllegalStateException::class.java) { store.migrate() }
        assertEquals("ROOT_NATIVE", store.memory)
        assertEquals("ROOT_TAP", store.durable)
        store.persistSucceeds = true
        assertEquals("ROOT_NATIVE", store.migrate())
        assertEquals("ROOT_NATIVE", store.durable)
        assertEquals(listOf("clear-pending", "persist-backend", "clear-pending", "persist-backend"), store.calls)
    }

    @Test fun userSelectingTunAfterAFailedCommitCancelsTheNativeRetry() {
        val store = Store("ROOT_TAP").also { it.persistSucceeds = false }
        assertThrows(IllegalStateException::class.java) { store.migrate() }
        store.memory = "TUN"; store.durable = "TUN"
        val before = store.calls.toList()
        assertEquals("TUN", store.migrate())
        assertEquals("TUN", store.durable)
        assertEquals(before, store.calls)
    }

    @Test fun successfulMigrationIsIdempotent() {
        val store = Store("ROOT_TAP")
        store.migrate(); val before = store.calls.toList(); store.migrate()
        assertEquals(before, store.calls)
    }

    @Test fun nativeUsesUtf8WithoutChangingTheSavedTunEncoding() {
        val saved = "GBK"
        assertEquals("UTF-8", BackendModePolicy.passwordEncoding("ROOT_NATIVE", saved))
        assertEquals("GBK", saved)
        assertTrue(Charsets.UTF_8.newEncoder().canEncode("\uD83D\uDE80"))
    }

    @Test fun unusedLegacyEncodingCannotBlockNative() {
        assertEquals("UTF-8", BackendModePolicy.passwordEncoding("ROOT_NATIVE", "invalid-old-value"))
    }

    @Test fun tunRetainsItsEncodingAndRejectsInvalidValues() {
        assertEquals("GBK", BackendModePolicy.passwordEncoding("TUN", "GBK"))
        assertEquals("UTF-8", BackendModePolicy.passwordEncoding("TUN", null))
        assertThrows(IllegalArgumentException::class.java) { BackendModePolicy.passwordEncoding("TUN", "invalid") }
    }
}
