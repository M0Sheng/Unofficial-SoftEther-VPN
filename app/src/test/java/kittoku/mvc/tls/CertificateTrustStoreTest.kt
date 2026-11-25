package kittoku.mvc.tls

import android.content.SharedPreferences
import kittoku.mvc.profile.ProfileStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

/** Real storage operations, including Android's memory-visible failed-commit semantics. */
class CertificateTrustStoreTest {
    private val first = "first-profile"
    private val second = "second-profile"
    private val third = "third-profile"
    private val oldPin = "ab".repeat(32)
    private val rememberedPin = "cd".repeat(32)
    private val newPin = "ef".repeat(32)
    private val legacyKey = "TLS_CERT_SHA256"
    private val pendingKey = "pending_certificate"

    @Test fun importsEveryOldEndpointIntoOnlyTheFirstProfile() {
        val (settings, trust) = preferences()
        trust.seed(oldKey("vpn.example", 5555), oldPin)
        trust.seed(oldKey("other.example", 443), rememberedPin)
        trust.seed(pendingKey, "{\"id\":\"legacy-review-without-profile\"}")
        val store = CertificateTrustStore(settings, trust)
        store.migrateLegacyTrust(first)
        assertEquals(oldPin, store.savedPin(first, "VPN.EXAMPLE", 5555))
        assertEquals(rememberedPin, store.savedPin(first, "other.example", 443))
        assertEquals("", store.savedPin(second, "vpn.example", 5555))
        assertEquals("", store.savedPin(third, "other.example", 443))
        assertFalse(trust.durableValues.containsKey(oldKey("vpn.example", 5555)))
        assertFalse(trust.durableValues.containsKey(pendingKey))
    }

    @Test fun scopedRememberedTrustWinsOverBothOldSources() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, newPin)
        trust.seed(oldKey("vpn.example", 5555), oldPin)
        trust.seed(key(first), rememberedPin)
        val store = CertificateTrustStore(settings, trust)
        store.migrateLegacyPin()
        assertEquals(rememberedPin, store.savedPin(first, "vpn.example", 5555))
        assertEquals(rememberedPin, trust.durableValues[key(first)])
        assertFalse(settings.durableValues.containsKey(legacyKey))
    }

    @Test fun normalizesManualPinAndCommitsDestinationBeforeRemovingItsSource() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, " \t" + oldPin.uppercase().chunked(2).joinToString(": ") + "\u2003\r\n")
        val store = CertificateTrustStore(settings, trust)
        store.migrateLegacyPin()
        assertEquals(oldPin, store.savedPin("vpn.example", 5555))
        assertEquals(oldPin, trust.durableValues[key(first)])
        assertFalse(settings.durableValues.containsKey(legacyKey))
        assertEquals(listOf("trust", "trust", "settings"), settings.commits)
        assertEquals(0, settings.applyCalls + trust.applyCalls)
    }

    @Test fun malformedManualPinsNeverCreateTrust() {
        for (invalid in listOf("", " \t", "ab".repeat(31), "gg".repeat(32), "01".repeat(33), 123)) {
            val (settings, trust) = preferences()
            settings.seed(legacyKey, invalid)
            val store = CertificateTrustStore(settings, trust)
            store.migrateLegacyPin()
            assertEquals("", store.savedPin(first, "vpn.example", 5555))
            assertFalse(settings.durableValues.containsKey(legacyKey))
        }
    }

    @Test fun validManualPinSurvivesAnInvalidFirstEndpoint() {
        for ((host, port) in listOf("" to 5555, "https://vpn.example" to 5555,
            "vpn.example/path" to 5555, "vpn.example" to 0, "vpn.example" to 65536)) {
            val (settings, trust) = preferences()
            settings.seed(legacyKey, oldPin)
            settings.seed("HOME_HOSTNAME", host); settings.seed("SSL_PORT", port.toString())
            val store = CertificateTrustStore(settings, trust)
            store.migrateLegacyPin()
            assertEquals(oldPin, settings.durableValues[legacyKey])
            assertFalse(trust.durableValues.containsKey(key(first)))
            settings.seed("HOME_HOSTNAME", "vpn.example"); settings.seed("SSL_PORT", "5555")
            store.migrateLegacyPin()
            assertEquals(oldPin, trust.durableValues[key(first)])
        }
    }

    @Test fun failedEndpointMigrationKeepsItsDiskSourceAndRetriesMemoryOnlyDestination() {
        val (settings, trust) = preferences()
        trust.seed(oldKey("vpn.example", 5555), oldPin)
        trust.failCommits = true
        val store = CertificateTrustStore(settings, trust)
        repeat(2) {
            assertThrows(IllegalStateException::class.java) { store.migrateLegacyPin() }
            assertEquals(oldPin, trust.durableValues[oldKey("vpn.example", 5555)])
            assertFalse(trust.durableValues.containsKey(key(first)))
            assertEquals("", store.savedPin(second, "vpn.example", 5555))
        }
        trust.failCommits = false
        CertificateTrustStore(settings, trust).migrateLegacyPin()
        assertEquals(oldPin, trust.durableValues[key(first)])
        assertFalse(trust.durableValues.containsKey(oldKey("vpn.example", 5555)))
    }

    @Test fun failedManualDestinationCommitRetainsLegacySourceUntilItIsDurable() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, oldPin)
        trust.failAtCommit = 2
        val store = CertificateTrustStore(settings, trust)
        assertThrows(IllegalStateException::class.java) { store.migrateLegacyPin() }
        assertEquals(oldPin, settings.durableValues[legacyKey])
        assertFalse(trust.durableValues.containsKey(key(first)))
        assertEquals(oldPin, store.savedPin(first, "vpn.example", 5555))
        store.migrateLegacyPin()
        assertEquals(oldPin, trust.durableValues[key(first)])
        assertFalse(settings.durableValues.containsKey(legacyKey))
    }

    @Test fun failedSourceRemovalIsFlushedAgainEvenAfterMemoryLostTheSource() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, oldPin)
        settings.failCommits = true
        assertThrows(IllegalStateException::class.java) { CertificateTrustStore(settings, trust).migrateLegacyPin() }
        assertFalse(settings.contains(legacyKey))
        assertEquals(oldPin, settings.durableValues[legacyKey])
        assertEquals(oldPin, trust.durableValues[key(first)])
        settings.failCommits = false
        CertificateTrustStore(settings, trust).migrateLegacyPin()
        settings.restoreFromDisk(); trust.restoreFromDisk()
        assertFalse(settings.contains(legacyKey))
        assertEquals(oldPin, CertificateTrustStore(settings, trust).savedPin(first, "vpn.example", 5555))
    }

    @Test fun laterProfileCannotImportTheManualPinAtItsOwnEndpoint() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, oldPin)
        settings.seed("CONNECTION_ACTIVE_PROFILE_ID", second)
        settings.seed("HOME_HOSTNAME", "second.example")
        val store = CertificateTrustStore(settings, trust)
        store.migrateLegacyPin()
        assertEquals("", store.savedPin(second, "second.example", 5555))
        assertEquals("", store.savedPin(first, "second.example", 5555))
        assertEquals(oldPin, settings.durableValues[legacyKey])
        settings.seed("CONNECTION_ACTIVE_PROFILE_ID", first)
        settings.seed("HOME_HOSTNAME", "vpn.example")
        store.migrateLegacyPin()
        assertEquals(oldPin, store.savedPin(first, "vpn.example", 5555))
    }

    @Test fun refusesAnAttemptToChangeTheFirstMigrationOwner() {
        val (settings, trust) = preferences()
        trust.seed(oldKey("vpn.example", 5555), oldPin)
        val store = CertificateTrustStore(settings, trust)
        assertThrows(IllegalArgumentException::class.java) { store.migrateLegacyTrust(second) }
        trust.seed("legacy_profile_trust_owner", third)
        assertThrows(IllegalStateException::class.java) { store.migrateLegacyTrust(first) }
        assertEquals(oldPin, trust.durableValues[oldKey("vpn.example", 5555)])
    }

    @Test fun savedPinNeverFallsBackToAnUnscopedEndpointPin() {
        val (settings, trust) = preferences()
        trust.seed(oldKey("vpn.example", 5555), oldPin)
        val store = CertificateTrustStore(settings, trust)
        assertEquals("", store.savedPin(first, "vpn.example", 5555))
        assertEquals("", store.savedPin(second, "vpn.example", 5555))
        assertTrue(settings.commits.isEmpty())
    }

    @Test fun forgottenTrustCannotBeRevivedByEitherLegacySourceAfterRestart() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, oldPin)
        trust.seed(oldKey("vpn.example", 5555), oldPin)
        val store = CertificateTrustStore(settings, trust)
        assertTrue(store.forget(first, "vpn.example", 5555))
        settings.restoreFromDisk(); trust.restoreFromDisk()
        val restarted = CertificateTrustStore(settings, trust)
        restarted.migrateLegacyPin()
        assertEquals("", restarted.savedPin(first, "vpn.example", 5555))
    }

    @Test fun forgettingOneProfileOrEndpointPreservesTheOthers() {
        val (settings, trust) = preferences()
        trust.seed(key(first), oldPin); trust.seed(key(second), rememberedPin)
        trust.seed(key(first, "other.example", 443), newPin)
        val store = CertificateTrustStore(settings, trust)
        assertTrue(store.forget(first, "vpn.example", 5555))
        assertEquals("", store.savedPin(first, "vpn.example", 5555))
        assertEquals(rememberedPin, store.savedPin(second, "vpn.example", 5555))
        assertEquals(newPin, store.savedPin(first, "other.example", 443))
    }

    @Test fun failedLegacyCleanupStopsForgettingInsteadOfRevivingTrustLater() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, oldPin); trust.seed(key(first), oldPin)
        settings.failCommits = true
        val store = CertificateTrustStore(settings, trust)
        assertFalse(store.forget(first, "vpn.example", 5555))
        assertEquals(oldPin, trust.durableValues[key(first)])
        settings.failCommits = false
        assertTrue(store.forget(first, "vpn.example", 5555))
        settings.restoreFromDisk(); trust.restoreFromDisk(); store.migrateLegacyPin()
        assertEquals("", store.savedPin(first, "vpn.example", 5555))
    }

    @Test fun failedFinalForgetCommitRestoresItsPinAndPendingInMemoryAndCanRetry() {
        val (settings, trust) = preferences()
        trust.seed(key(first), oldPin)
        trust.seed(key(second), rememberedPin)
        val store = CertificateTrustStore(settings, trust)
        val pending = store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review(oldPin))!!
        val pendingRaw = trust.values["pending_certificate"]
        // beginReview was trust commit 1; migration is commit 2; erase is commit 3.
        trust.failAtCommit = 3
        assertFalse(store.forget(first, "vpn.example", 5555))
        assertEquals(oldPin, trust.values[key(first)])
        assertEquals(oldPin, trust.durableValues[key(first)])
        assertEquals(pendingRaw, trust.values["pending_certificate"])
        assertEquals(pendingRaw, trust.durableValues["pending_certificate"])
        assertEquals(rememberedPin, trust.values[key(second)])
        assertEquals(rememberedPin, trust.durableValues[key(second)])
        assertEquals(pending.requestId, store.pending()!!.requestId)
        assertTrue(store.forget(first, "vpn.example", 5555))
        assertFalse(trust.durableValues.containsKey(key(first)))
        assertFalse(trust.durableValues.containsKey("pending_certificate"))
        assertEquals(rememberedPin, trust.durableValues[key(second)])
    }

    @Test fun inactiveFirstProfileCannotReportForgottenWhileItsUnresolvedLegacyPinCanRevive() {
        val (settings, trust) = preferences()
        settings.seed(legacyKey, oldPin)
        settings.seed("HOME_HOSTNAME", "")
        trust.seed(oldKey("vpn.example", 5555), oldPin)
        val store = CertificateTrustStore(settings, trust)
        store.migrateLegacyPin()
        settings.seed("HOME_HOSTNAME", "vpn.example")
        settings.seed("CONNECTION_ACTIVE_PROFILE_ID", second)
        assertFalse(store.forget(first, "vpn.example", 5555))
        assertEquals(oldPin, settings.durableValues[legacyKey])
        assertEquals(oldPin, trust.durableValues[key(first)])
        settings.seed("CONNECTION_ACTIVE_PROFILE_ID", first)
        assertTrue(store.forget(first, "vpn.example", 5555))
        settings.restoreFromDisk(); trust.restoreFromDisk(); store.migrateLegacyPin()
        assertEquals("", store.savedPin(first, "vpn.example", 5555))
        assertFalse(settings.durableValues.containsKey(legacyKey))
    }

    @Test fun acceptsOnlyTheExactFrozenProfileDecisionAndWritesOnlyThatProfile() {
        val (settings, trust) = preferences()
        val store = CertificateTrustStore(settings, trust)
        val review = store.beginReview(first, "VPN.EXAMPLE", 5555, "ROOT_NATIVE", review())!!
        assertEquals(first, store.pending()!!.profileId)
        assertFalse(store.accept("another-request"))
        assertTrue(store.accept(review.requestId))
        assertEquals(newPin, trust.durableValues[key(first)])
        assertEquals("", store.savedPin(second, "vpn.example", 5555))
        assertFalse(trust.contains(pendingKey))
    }

    @Test fun switchingProfilesWithTheSameEndpointInvalidatesThePendingApproval() {
        val (settings, trust) = preferences()
        val store = CertificateTrustStore(settings, trust)
        val pending = store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review())!!
        settings.seed("CONNECTION_ACTIVE_PROFILE_ID", second)
        assertNull(store.pending())
        assertFalse(store.accept(pending.requestId))
        settings.seed("CONNECTION_ACTIVE_PROFILE_ID", first)
        assertNull(store.pending())
        assertFalse(store.accept(pending.requestId))
        assertEquals("", store.savedPin(first, "vpn.example", 5555))
    }

    @Test fun aLateReviewFromAnOldSessionCannotReplaceTheCurrentProfilesPendingReview() {
        val (settings, trust) = preferences()
        settings.seed("CONNECTION_ACTIVE_PROFILE_ID", second)
        val store = CertificateTrustStore(settings, trust)
        val current = store.beginReview(second, "vpn.example", 5555, "ROOT_NATIVE", review())!!
        assertNull(store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review()))
        assertEquals(current.requestId, store.pending()!!.requestId)
    }

    @Test fun profileSwitchAndApprovalUseTheSameAtomicLock() {
        val (settings, trust) = preferences()
        val store = CertificateTrustStore(settings, trust)
        val pending = store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review())!!
        val started = CountDownLatch(1)
        val result = AtomicReference<Boolean>()
        lateinit var accepting: Thread
        synchronized(ProfileStore.LOCK) {
            accepting = Thread {
                started.countDown()
                result.set(store.accept(pending.requestId))
            }.apply { start() }
            assertTrue(started.await(2, TimeUnit.SECONDS))
            assertTrue(store.clearPending())
            settings.seed("CONNECTION_ACTIVE_PROFILE_ID", second)
        }
        accepting.join(2_000)
        assertFalse(accepting.isAlive)
        assertEquals(false, result.get())
        assertFalse(trust.durableValues.containsKey(key(first)))
        assertFalse(trust.durableValues.containsKey(key(second)))
    }

    @Test fun changingEndpointBackendOrPreviousPinWhileReviewingRejectsAcceptance() {
        for (change in listOf<(MemoryPreferences, MemoryPreferences) -> Unit>(
            { settings, _ -> settings.seed("HOME_HOSTNAME", "other.example") },
            { settings, _ -> settings.seed("SSL_PORT", "443") },
            { settings, _ -> settings.seed("BACKEND_MODE", "TUN") },
            { _, trust -> trust.seed(key(first), rememberedPin) }
        )) {
            val (settings, trust) = preferences()
            val store = CertificateTrustStore(settings, trust)
            val pending = store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review())!!
            change(settings, trust)
            assertFalse(store.accept(pending.requestId))
            assertFalse(trust.durableValues.values.contains(newPin))
        }
    }

    @Test fun failedMigrationCannotExposeAPendingApprovalToUiOrApproveIt() {
        val (settings, trust) = preferences()
        val store = CertificateTrustStore(settings, trust)
        val pending = store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review())!!
        trust.failCommits = true
        assertNull(store.pending())
        assertFalse(store.accept(pending.requestId))
        assertFalse(trust.durableValues.containsKey(key(first)))
    }

    @Test fun duplicationCopiesIndependentTrustedPinsButNeverThePendingDecision() {
        val (settings, trust) = preferences()
        trust.seed(key(first), oldPin); trust.seed(key(first, "other.example", 443), rememberedPin)
        trust.seed(key(second, "obsolete.example", 443), newPin)
        trust.seed(key(third), rememberedPin)
        val store = CertificateTrustStore(settings, trust)
        val pending = store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review(oldPin))!!
        assertTrue(store.copyProfileTrust(first, second))
        assertEquals(oldPin, store.savedPin(second, "vpn.example", 5555))
        assertEquals(rememberedPin, store.savedPin(second, "other.example", 443))
        assertEquals("", store.savedPin(second, "obsolete.example", 443))
        assertEquals(pending.requestId, store.pending()!!.requestId)
        assertEquals(rememberedPin, store.savedPin(third, "vpn.example", 5555))
        assertTrue(store.forget(second, "vpn.example", 5555))
        assertEquals(oldPin, store.savedPin(first, "vpn.example", 5555))
    }

    @Test fun failedDuplicateCommitIsRetryableAndDoesNotCreateDurablePartialTrust() {
        val (settings, trust) = preferences()
        trust.seed(key(first), oldPin)
        trust.failAtCommit = 2 // Migration flush succeeds; copy itself fails.
        val store = CertificateTrustStore(settings, trust)
        assertFalse(store.copyProfileTrust(first, second))
        assertFalse(trust.durableValues.containsKey(key(second)))
        assertTrue(store.copyProfileTrust(first, second))
        assertEquals(oldPin, trust.durableValues[key(second)])
    }

    @Test fun deletingAProfileRemovesOnlyItsPinsAndItsPendingReviewDurably() {
        val (settings, trust) = preferences()
        trust.seed(key(first), oldPin); trust.seed(key(second), rememberedPin)
        val store = CertificateTrustStore(settings, trust)
        val pending = store.beginReview(first, "vpn.example", 5555, "ROOT_NATIVE", review(oldPin))!!
        assertTrue(store.deleteProfileTrust(second))
        assertEquals(pending.requestId, store.pending()!!.requestId)
        assertTrue(store.deleteProfileTrust(first))
        assertFalse(trust.durableValues.containsKey(key(first)))
        assertFalse(trust.durableValues.containsKey(key(second)))
        assertFalse(trust.durableValues.containsKey(pendingKey))
    }

    @Test fun failedDeleteCommitRetriesEvenWhenMemoryAlreadyLostThePins() {
        val (settings, trust) = preferences()
        trust.seed(key(second), rememberedPin)
        trust.failAtCommit = 2
        val store = CertificateTrustStore(settings, trust)
        assertFalse(store.deleteProfileTrust(second))
        assertEquals(rememberedPin, trust.durableValues[key(second)])
        assertTrue(store.deleteProfileTrust(second))
        assertFalse(trust.durableValues.containsKey(key(second)))
    }

    private fun review(previous: String = ""): CertificateReviewException {
        val now = System.currentTimeMillis()
        return CertificateReviewException(CertificateIdentity(newPin, "CN=vpn.example", "CN=test issuer",
            now - 10_000, now + 60_000, "DNS:vpn.example"), previous, Exception("test untrusted leaf"))
    }

    private fun preferences(): Pair<MemoryPreferences, MemoryPreferences> {
        val commits = mutableListOf<String>()
        return MemoryPreferences("settings", commits).apply {
            seed("CONNECTION_ACTIVE_PROFILE_ID", first); seed("CONNECTION_FIRST_PROFILE_ID", first)
            seed("HOME_HOSTNAME", "vpn.example"); seed("SSL_PORT", "5555"); seed("BACKEND_MODE", "ROOT_NATIVE")
        } to MemoryPreferences("trust", commits)
    }

    private fun key(profile: String, host: String = "vpn.example", port: Int = 5555) =
        CertificateProfileScope.key(profile, CertificateEndpoint.of(host, port))
    private fun oldKey(host: String, port: Int) = "trusted_" + CertificateEndpoint.of(host, port).key

    private class MemoryPreferences(val label: String, val commits: MutableList<String>) : SharedPreferences {
        val values = linkedMapOf<String, Any>()
        val durableValues = linkedMapOf<String, Any>()
        var failCommits = false
        var failAtCommit = -1
        private var commitCount = 0
        var applyCalls = 0
        fun seed(key: String, value: Any) { values[key] = value; durableValues[key] = value }
        fun restoreFromDisk() { values.clear(); values.putAll(durableValues) }
        override fun getAll(): MutableMap<String, *> = values.toMutableMap()
        override fun contains(key: String?): Boolean = values.containsKey(key)
        override fun getString(key: String?, defValue: String?): String? =
            if (values.containsKey(key)) values[key] as String else defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            if (values.containsKey(key)) (values[key] as Set<String>).toMutableSet() else defValues
        override fun getInt(key: String?, defValue: Int): Int = values[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = values[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = values[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = values[key] as? Boolean ?: defValue
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val edits = linkedMapOf<String, Any?>()
            private var clearAll = false
            private fun put(key: String?, value: Any?): SharedPreferences.Editor {
                requireNotNull(key); edits[key] = value; return this
            }
            override fun putString(key: String?, value: String?) = put(key, value)
            override fun putStringSet(key: String?, values: MutableSet<String>?) = put(key, values?.toSet())
            override fun putInt(key: String?, value: Int) = put(key, value)
            override fun putLong(key: String?, value: Long) = put(key, value)
            override fun putFloat(key: String?, value: Float) = put(key, value)
            override fun putBoolean(key: String?, value: Boolean) = put(key, value)
            override fun remove(key: String?) = put(key, null)
            override fun clear(): SharedPreferences.Editor { clearAll = true; return this }
            override fun commit(): Boolean {
                commits += label; commitCount++
                if (clearAll) values.clear()
                edits.forEach { (key, value) -> if (value == null) values.remove(key) else values[key] = value }
                if (failCommits || commitCount == failAtCommit) return false
                durableValues.clear(); durableValues.putAll(values); return true
            }
            override fun apply() { applyCalls++; commit() }
        }
    }
}
