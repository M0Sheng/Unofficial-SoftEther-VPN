package kittoku.mvc.profile

import android.content.SharedPreferences
import kittoku.mvc.tls.CertificateEndpoint
import kittoku.mvc.tls.CertificateProfileScope
import kittoku.mvc.tls.CertificateTrustStore
import kittoku.mvc.tls.CertificateIdentity
import kittoku.mvc.tls.CertificateReviewException
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Locale

/** Real profile and certificate stores; only Android preference files are held in memory. */
class ProfileCertificateStoreTest {
    private val firstPin = "ab".repeat(32)
    private val secondPin = "cd".repeat(32)

    private class Fixture(legacy: Boolean = true) {
        val settings = MemoryPreferences().apply {
            if (legacy) {
                seed("HOME_HOSTNAME", "vpn.example"); seed("SSL_PORT", "5555")
                seed("HOME_HUB", "DEFAULT"); seed("HOME_USERNAME", "fixture-user")
                seed("HOME_PASSWORD", "fixture-secret"); seed("BACKEND_MODE", "ROOT_NATIVE")
            }
        }
        val trustPreferences = MemoryPreferences()
        val trust = CertificateTrustStore(settings, trustPreferences)
        private var nextId = 0
        val profiles = ProfileStore(settings, object : ProfileTrust {
            override fun migrate(firstId: String) = trust.migrateLegacyTrust(firstId)
            override fun clearPending() = trust.clearPending()
            override fun copy(fromId: String, toId: String) = trust.copyProfileTrust(fromId, toId)
            override fun delete(id: String) = trust.deleteProfileTrust(id)
            override fun installImportedCertificate(profileId: String, endpoint: CertificateEndpoint, pin: String, der: ByteArray?) =
                trust.installImportedCertificate(profileId, endpoint, pin, der)
        }) { "certificate-profile-${++nextId}" }
        val certificates = ProfileCertificateStore(profiles, trust)
        private val initialId = profiles.ensureInitialized()
        val firstId get() = requireNotNull(initialId)
        fun seedPin(id: String, pin: String, host: String = "vpn.example", port: Int = 5555) {
            trustPreferences.seed(CertificateProfileScope.key(id, CertificateEndpoint.of(host, port)), pin)
        }
        fun savedProfile(host: String = "vpn.example", port: String? = "5555"): String {
            val id = profiles.createSaved("Other")
            val original = profiles.readForEdit(id)
            val values = original.values.toMutableMap().apply {
                put("HOME_HOSTNAME", host)
                if (port == null) remove("SSL_PORT") else put("SSL_PORT", port)
            }
            profiles.saveProfile(original, original.name, values)
            return id
        }
    }

    @Test fun exposesOnlyTheCertificatePreferencesForUiListening() {
        val f = Fixture()
        assertSame(f.trustPreferences, f.certificates.preferences)
        assertNotSame(f.settings, f.certificates.preferences)
    }

    @Test fun readsTheFixedProfileAndNormalizesItsEndpoint() {
        val f = Fixture()
        f.settings.seed("HOME_HOSTNAME", "  VPN.EXAMPLE  ")
        f.seedPin(f.firstId, firstPin)
        val snapshot = f.certificates.read(f.firstId)
        assertEquals(ProfileCertificateSnapshot(f.firstId, CertificateEndpoint.of("vpn.example", 5555), firstPin), snapshot)
        assertFalse(snapshot.toString().contains("fixture-secret"))
        assertFalse(snapshot.toString().contains("fixture-user"))
    }

    @Test fun hubApprovalAtSavedEndpointIsImmediatelyAvailableToConnectionsForOnlyThatProfile() {
        val f = Fixture()
        val other = f.savedProfile()
        val expected = f.profiles.readForEdit(f.firstId)
        val approval = hubApproval()
        assertEquals("", f.certificates.lookupPin(expected, approval.endpoint))
        assertTrue(f.certificates.rememberHubCertificate(expected, approval))
        val restarted = CertificateTrustStore(f.settings, f.trustPreferences)
        assertEquals(firstPin, restarted.savedPin(f.firstId, "VPN.EXAMPLE", 5555))
        assertEquals("", restarted.savedPin(f.firstId, "vpn.example", 443))
        assertEquals("", restarted.savedPin(other, "vpn.example", 5555))
    }

    @Test fun hubApprovalAtDraftEndpointIsPublishedOnlyWhenSavingThatEndpoint() {
        val f = Fixture()
        f.seedPin(f.firstId, secondPin)
        val expected = f.profiles.readForEdit(f.firstId)
        val edited = expected.values + ("SSL_PORT" to "443")
        val approval = hubApproval(port = 443)
        assertFalse(f.certificates.rememberHubCertificate(expected, approval))
        assertEquals("", f.certificates.lookupPin(expected, approval.endpoint))
        assertThrows(IllegalStateException::class.java) {
            f.certificates.saveProfileWithHubCertificate(expected, "Edited", edited, hubApproval(port = 444))
        }
        f.certificates.saveProfileWithHubCertificate(expected, "Edited", edited, approval)
        assertEquals("Edited", f.profiles.readForEdit(f.firstId).name)
        assertEquals(ProfileCertificateSnapshot(f.firstId, approval.endpoint, firstPin), f.certificates.read(f.firstId))
        assertEquals(secondPin, f.trust.savedPin(f.firstId, "vpn.example", 5555))
        assertNull(f.certificates.lookupPin(expected, approval.endpoint))
    }

    @Test fun hubApprovalRejectsConcurrentOrHistoricalPinsAndStaleProfiles() {
        val f = Fixture()
        val expected = f.profiles.readForEdit(f.firstId)
        val otherPort = hubApproval(port = 443)
        f.seedPin(f.firstId, secondPin, port = 443)
        assertEquals(secondPin, f.certificates.lookupPin(expected, otherPort.endpoint))
        val values = expected.values + ("SSL_PORT" to "443")
        for (approval in listOf(otherPort, otherPort.copy(expectedPin = secondPin))) {
            assertThrows(IllegalStateException::class.java) {
                f.certificates.saveProfileWithHubCertificate(expected, "Changed", values, approval)
            }
        }
        assertEquals(secondPin, f.trust.savedPin(f.firstId, "vpn.example", 443))
        assertEquals(expected, f.profiles.readForEdit(f.firstId))
        f.settings.seed("HOME_HOSTNAME", "other.example")
        assertNull(f.certificates.lookupPin(expected, hubApproval().endpoint))
        assertFalse(f.certificates.rememberHubCertificate(expected, hubApproval()))
        assertEquals("", f.trust.savedPin(f.firstId, "vpn.example", 5555))
    }

    @Test fun hubApprovalRejectsInvalidIdentityAndTheActiveConnectedProfile() {
        val f = Fixture()
        val expected = f.profiles.readForEdit(f.firstId)
        val approval = hubApproval()
        assertFalse(f.certificates.rememberHubCertificate(expected,
            approval.copy(identity = approval.identity.copy(notAfterMillis = 1L))))
        assertFalse(f.certificates.rememberHubCertificate(expected,
            approval.copy(identity = approval.identity.copy(sha256 = "invalid pin"))))
        f.settings.seed("HOME_CONNECTOR", true)
        assertFalse(f.certificates.rememberHubCertificate(expected, approval))
        assertEquals("", f.certificates.read(f.firstId).pin)
    }

    @Test fun failedHubCertificateAndProfileWritesLeaveNoPinOrProfileChangeAndCanBeRetried() {
        val f = Fixture()
        f.seedPin(f.firstId, secondPin)
        val expected = f.profiles.readForEdit(f.firstId)
        val approval = hubApproval(port = 443)
        val values = expected.values + ("SSL_PORT" to "443")
        val beforeSettings = f.settings.durable.toMap()
        val beforeTrust = f.trustPreferences.durable.toMap()
        fun save() = f.certificates.saveProfileWithHubCertificate(expected, "Edited", values, approval)
        f.trustPreferences.failAtCommit = f.trustPreferences.commitCount + 1
        assertThrows(IllegalStateException::class.java) { save() }
        assertEquals(beforeTrust, f.trustPreferences.values)
        assertEquals(beforeTrust, f.trustPreferences.durable)
        assertEquals(beforeSettings, f.settings.durable)
        f.settings.failAtCommit = f.settings.commitCount + 1
        assertThrows(IllegalStateException::class.java) { save() }
        assertEquals(beforeTrust, f.trustPreferences.values)
        assertEquals(beforeTrust, f.trustPreferences.durable)
        assertEquals(beforeSettings, f.settings.values)
        assertEquals(beforeSettings, f.settings.durable)
        save()
        assertEquals(firstPin, f.trust.savedPin(f.firstId, "vpn.example", 443))
        assertEquals(secondPin, f.trust.savedPin(f.firstId, "vpn.example", 5555))
    }

    @Test fun missingPortUses5555ButAnExplicitInvalidPortHasNoCertificateEndpoint() {
        val f = Fixture()
        val withoutPort = f.savedProfile(port = null)
        f.seedPin(withoutPort, secondPin)
        assertEquals(5555, f.certificates.read(withoutPort).endpoint!!.port)
        assertEquals(secondPin, f.certificates.read(withoutPort).pin)
        for (invalid in listOf("", "0", "65536", "not-a-port", " 5555 ")) {
            f.settings.seed("SSL_PORT", invalid)
            val snapshot = f.certificates.read(f.firstId)
            assertNull(snapshot.endpoint)
            assertEquals("", snapshot.pin)
            assertFalse(f.certificates.forget(snapshot))
        }
    }

    @Test fun blankOrUrlStyleHostsCannotAccidentallyReadAnotherEndpointsTrust() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        for (invalid in listOf("", "  ", "https://vpn.example", "vpn.example/path", "vpn example", "vpn.example\nother")) {
            f.settings.seed("HOME_HOSTNAME", invalid)
            val snapshot = f.certificates.read(f.firstId)
            assertNull(snapshot.endpoint)
            assertEquals("", snapshot.pin)
        }
    }

    @Test fun readsBracketedIpv6UsingTheSameCanonicalEndpointAsTls() {
        val f = Fixture()
        f.settings.seed("HOME_HOSTNAME", " [2001:DB8::A] ")
        f.seedPin(f.firstId, firstPin, "2001:db8::a")
        assertEquals("2001:db8::a", f.certificates.read(f.firstId).endpoint!!.host)
        assertEquals(firstPin, f.certificates.read(f.firstId).pin)
    }

    @Test fun sameEndpointInTwoProfilesHasIndependentPinsAndInactiveReadUsesSavedValues() {
        val f = Fixture()
        val other = f.savedProfile()
        f.seedPin(f.firstId, firstPin); f.seedPin(other, secondPin)
        f.settings.seed("HOME_HOSTNAME", "working-draft.example")
        assertEquals("", f.certificates.read(f.firstId).pin)
        assertEquals(secondPin, f.certificates.read(other).pin)
        assertEquals("vpn.example", f.certificates.read(other).endpoint!!.host)
        assertEquals(f.firstId, f.profiles.state().activeId)
    }

    @Test fun aNewProfileAtTheSameEndpointDoesNotInheritTheOtherProfilesPin() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val other = f.savedProfile()
        assertEquals("", f.certificates.read(other).pin)
        assertEquals(firstPin, f.certificates.read(f.firstId).pin)
    }

    @Test fun renamingPreservesTheIdentityAndClearingAnExplicitCopyDoesNotHurtItsSource() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val copy = f.profiles.copy(f.firstId, "Duplicate")
        f.profiles.rename(copy, "Renamed duplicate")
        val snapshot = f.certificates.read(copy)
        assertEquals(firstPin, snapshot.pin)
        assertTrue(f.certificates.forget(snapshot))
        assertEquals("", f.certificates.read(copy).pin)
        assertEquals(firstPin, f.certificates.read(f.firstId).pin)
    }

    @Test fun activeBusyTargetCannotBeClearedAfterItsDialogWasOpened() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val snapshot = f.certificates.read(f.firstId)
        f.settings.seed("HOME_CONNECTOR", true)
        assertFalse(f.certificates.forget(snapshot))
        assertEquals(firstPin, f.certificates.read(f.firstId).pin)
        assertTrue(f.settings.getBoolean("HOME_CONNECTOR", false))
    }

    @Test fun inactiveCertificateCanBeClearedWhileAnotherProfileIsConnected() {
        val f = Fixture()
        val inactive = f.savedProfile()
        f.seedPin(f.firstId, firstPin); f.seedPin(inactive, secondPin)
        f.settings.seed("HOME_CONNECTOR", true)
        f.settings.seed("HOME_STATUS", "connected")
        val before = f.settings.values.toMap()
        assertTrue(f.certificates.forget(f.certificates.read(inactive)))
        assertEquals(firstPin, f.certificates.read(f.firstId).pin)
        assertEquals("", f.certificates.read(inactive).pin)
        assertEquals(before, f.settings.values)
    }

    @Test fun laterSelectionCannotRedirectAnOlderTargetsClearActionToCurrent() {
        val f = Fixture()
        val other = f.savedProfile()
        f.seedPin(f.firstId, firstPin); f.seedPin(other, secondPin)
        val originalTarget = f.certificates.read(f.firstId)
        f.profiles.select(other, true)
        assertTrue(f.certificates.forget(originalTarget))
        assertEquals("", f.certificates.read(f.firstId).pin)
        assertEquals(secondPin, f.certificates.read(other).pin)
        assertEquals(other, f.profiles.state().activeId)
    }

    @Test fun changedHostOrPortInvalidatesTheOldSnapshotWithoutDeletingAnyPin() {
        for ((host, port) in listOf("other.example" to "5555", "vpn.example" to "443")) {
            val f = Fixture()
            f.seedPin(f.firstId, firstPin)
            val old = f.certificates.read(f.firstId)
            f.settings.seed("HOME_HOSTNAME", host); f.settings.seed("SSL_PORT", port)
            f.seedPin(f.firstId, secondPin, host, port.toInt())
            assertFalse(f.certificates.forget(old))
            assertEquals(firstPin, f.trust.savedPin(f.firstId, "vpn.example", 5555))
            assertEquals(secondPin, f.certificates.read(f.firstId).pin)
        }
    }

    @Test fun aReplacedPinCannotBeClearedUsingThePreviousSnapshot() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val old = f.certificates.read(f.firstId)
        f.seedPin(f.firstId, secondPin)
        assertFalse(f.certificates.forget(old))
        assertEquals(secondPin, f.certificates.read(f.firstId).pin)
    }

    @Test fun deletedProfilesCannotBeReadOrClearedAsIfTheyWereTheCurrentProfile() {
        val f = Fixture()
        val inactive = f.savedProfile()
        f.seedPin(f.firstId, firstPin); f.seedPin(inactive, secondPin)
        val old = f.certificates.read(inactive)
        f.profiles.delete(inactive)
        assertThrows(IllegalStateException::class.java) { f.certificates.read(inactive) }
        assertFalse(f.certificates.forget(old))
        assertEquals(firstPin, f.certificates.read(f.firstId).pin)
    }

    @Test fun emptyOrAlreadyForgottenSnapshotsNeverCreateOrRemoveOtherTrust() {
        val f = Fixture()
        val empty = f.certificates.read(f.firstId)
        assertFalse(f.certificates.forget(empty))
        f.seedPin(f.firstId, firstPin)
        val pinned = f.certificates.read(f.firstId)
        assertTrue(f.certificates.forget(pinned))
        assertFalse(f.certificates.forget(pinned))
    }

    @Test fun failedCertificateEraseCommitReturnsFalseAndDoesNotClaimDurableRemoval() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val snapshot = f.certificates.read(f.firstId)
        // First trust commit flushes migration; the second is the actual pin erase.
        f.trustPreferences.failAtCommit = f.trustPreferences.commitCount + 2
        assertFalse(f.certificates.forget(snapshot))
        val key = CertificateProfileScope.key(f.firstId, snapshot.endpoint!!)
        assertEquals(firstPin, f.trustPreferences.durable[key])
        assertEquals(firstPin, f.certificates.read(f.firstId).pin)
        assertEquals(f.firstId, f.profiles.state().activeId)
        assertTrue(f.certificates.forget(snapshot))
        assertEquals("", f.certificates.read(f.firstId).pin)
        assertFalse(f.trustPreferences.durable.containsKey(key))
    }

    @Test fun importedDerIsBoundToOnlyTheNewProfileAndExactEndpointAndIsDefensivelyCopied() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val pending = f.trust.beginReview(f.firstId, "vpn.example", 5555, "ROOT_NATIVE", review(secondPin, firstPin))!!
        f.settings.seed("HOME_CONNECTOR", true)
        val beforeSettings = f.settings.values.toMap()
        val bytes = certificate().encoded
        val original = bytes.clone()
        val pin = fingerprint(original)
        val id = f.profiles.importSaved(imported(bytes), true)
        assertEquals(beforeSettings.filterKeys { it != ProfileStore.REGISTRY_KEY },
            f.settings.values.filterKeys { it != ProfileStore.REGISTRY_KEY })
        assertEquals(f.firstId, f.profiles.state().activeId)
        assertEquals(pending.requestId, f.trust.pending()!!.requestId)
        assertEquals(firstPin, f.trust.savedPin(f.firstId, "vpn.example", 5555))
        assertEquals(pin, f.trust.savedPin(id, "vpn.example", 5555))
        bytes[0] = 0
        assertArrayEquals(original, f.trust.savedCertificateDer(id, "VPN.EXAMPLE", 5555))
        val returned = f.trust.savedCertificateDer(id, "vpn.example", 5555)!!
        returned[0] = 0
        assertArrayEquals(original, f.trust.savedCertificateDer(id, "vpn.example", 5555))
        assertNull(f.trust.savedCertificateDer(f.firstId, "vpn.example", 5555))
        assertNull(f.trust.savedCertificateDer(id, "vpn.example", 443))
        assertNull(f.trust.savedCertificateDer(id, "other.example", 5555))
    }

    @Test fun failedImportedTrustCommitRollsMemoryBackAndPreservesOtherPinsAndPendingBeforeRetry() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val pending = f.trust.beginReview(f.firstId, "vpn.example", 5555, "ROOT_NATIVE", review(secondPin, firstPin))!!
        val beforeSettings = f.settings.values.toMap()
        val beforeMemory = f.trustPreferences.values.toMap()
        val beforeDisk = f.trustPreferences.durable.toMap()
        f.trustPreferences.failAtCommit = f.trustPreferences.commitCount + 1
        assertThrows(IllegalStateException::class.java) { f.profiles.importSaved(imported(), true) }
        assertEquals(beforeSettings, f.settings.values)
        assertEquals(beforeMemory, f.trustPreferences.values)
        assertEquals(beforeDisk, f.trustPreferences.durable)
        assertEquals(pending.requestId, f.trust.pending()!!.requestId)
        val id = f.profiles.importSaved(imported(), true)
        assertArrayEquals(certificate().encoded, f.trust.savedCertificateDer(id, "vpn.example", 5555))
        assertEquals(firstPin, f.trust.savedPin(f.firstId, "vpn.example", 5555))
    }

    @Test fun failedRegistryPublishCleansTheImportedPinAndDerButRetainsTheOriginalCertificate() {
        val f = Fixture()
        f.seedPin(f.firstId, firstPin)
        val pending = f.trust.beginReview(f.firstId, "vpn.example", 5555, "ROOT_NATIVE", review(secondPin, firstPin))!!
        f.settings.failAtCommit = f.settings.commitCount + 1
        assertThrows(IllegalStateException::class.java) { f.profiles.importSaved(imported(), true) }
        assertEquals(1, f.profiles.state().profiles.size)
        assertFalse(f.trustPreferences.values.keys.any { it.startsWith(CertificateProfileScope.prefix("certificate-profile-2")) })
        assertFalse(f.trustPreferences.durable.keys.any { it.startsWith(CertificateProfileScope.prefix("certificate-profile-2")) })
        assertEquals(firstPin, f.trust.savedPin(f.firstId, "vpn.example", 5555))
        assertEquals(pending.requestId, f.trust.pending()!!.requestId)
    }

    @Test fun firstImportActivatesWithItsCertificateAndRollsBackStagedTrustIfPublishFails() {
        val f = Fixture(legacy = false)
        val profile = imported()
        f.settings.failAtCommit = f.settings.commitCount + 1
        assertThrows(IllegalStateException::class.java) { f.profiles.importSaved(profile, true) }
        assertNull(f.profiles.state().activeId)
        assertTrue(f.profiles.state().profiles.isEmpty())
        val failedPrefix = CertificateProfileScope.prefix("certificate-profile-1")
        assertFalse(f.trustPreferences.values.keys.any { it.startsWith(failedPrefix) })
        assertFalse(f.trustPreferences.durable.keys.any { it.startsWith(failedPrefix) })

        val id = f.profiles.importSaved(profile, true)
        assertEquals(id, f.profiles.state().activeId)
        assertEquals(profile.certificatePin, f.certificates.read(id).pin)
        assertEquals("ALL", f.profiles.readForEdit(id).values["TUN_DESTINATION_MODE"])
    }

    @Test fun importedScopeRejectsRegisteredProfilesExistingPinsMismatchingAndTrailingDer() {
        val f = Fixture()
        val endpoint = CertificateEndpoint.of("vpn.example", 5555)
        val der = certificate().encoded
        val pin = fingerprint(der)
        assertFalse(f.trust.installImportedCertificate(f.firstId, endpoint, pin, der))
        val other = f.savedProfile()
        assertFalse(f.trust.installImportedCertificate(other, endpoint, pin, der))
        assertFalse(f.trust.installImportedCertificate("unpublished", endpoint, firstPin, der))
        assertFalse(f.trust.installImportedCertificate("unpublished", endpoint, pin, der + byteArrayOf(0)))
        assertFalse(f.trust.installImportedCertificate("unpublished", endpoint, pin, byteArrayOf(1, 2, 3)))
        assertTrue(f.trust.installImportedCertificate("unpublished", endpoint, pin, der))
        assertFalse(f.trust.installImportedCertificate("unpublished", endpoint, secondPin, null))
        assertEquals(pin, f.trust.savedPin("unpublished", "vpn.example", 5555))
        assertArrayEquals(der, f.trust.savedCertificateDer("unpublished", "vpn.example", 5555))
    }

    @Test fun certificateDerFollowsExplicitProfileCopyAndDeleteWithoutTouchingItsSource() {
        val f = Fixture()
        val source = f.profiles.importSaved(imported(), true)
        val copy = f.profiles.copy(source, "Copy")
        assertArrayEquals(certificate().encoded, f.trust.savedCertificateDer(copy, "vpn.example", 5555))
        f.profiles.delete(copy)
        assertNull(f.trust.savedCertificateDer(copy, "vpn.example", 5555))
        assertFalse(f.trustPreferences.durable.keys.any { it.startsWith(CertificateProfileScope.prefix(copy)) })
        assertArrayEquals(certificate().encoded, f.trust.savedCertificateDer(source, "vpn.example", 5555))
    }

    @Test fun forgetRemovesDerWithItsPinAndFailedEraseRestoresBothBeforeRetry() {
        val f = Fixture()
        val id = f.profiles.importSaved(imported(), true)
        val snapshot = f.certificates.read(id)
        f.trustPreferences.failAtCommit = f.trustPreferences.commitCount + 2
        assertFalse(f.certificates.forget(snapshot))
        assertEquals(snapshot.pin, f.trust.savedPin(id, "vpn.example", 5555))
        assertArrayEquals(certificate().encoded, f.trust.savedCertificateDer(id, "vpn.example", 5555))
        val key = CertificateProfileScope.key(id, snapshot.endpoint!!)
        assertTrue(f.trustPreferences.durable.containsKey(key + "_der"))
        assertTrue(f.certificates.forget(snapshot))
        assertEquals("", f.trust.savedPin(id, "vpn.example", 5555))
        assertNull(f.trust.savedCertificateDer(id, "vpn.example", 5555))
        assertFalse(f.trustPreferences.durable.containsKey(key + "_der"))
    }

    @Test fun acceptingTheSamePinRetainsDerButAChangedPinDiscardsIt() {
        val f = Fixture()
        val id = f.profiles.importSaved(imported(), true)
        f.profiles.select(id, false)
        val pin = fingerprint(certificate().encoded)
        val same = f.trust.beginReview(id, "vpn.example", 5555, "ROOT_NATIVE", review(pin, pin))!!
        assertTrue(f.trust.accept(same.requestId))
        assertArrayEquals(certificate().encoded, f.trust.savedCertificateDer(id, "vpn.example", 5555))
        val changed = f.trust.beginReview(id, "vpn.example", 5555, "ROOT_NATIVE", review(secondPin, pin))!!
        assertTrue(f.trust.accept(changed.requestId))
        assertEquals(secondPin, f.trust.savedPin(id, "vpn.example", 5555))
        assertNull(f.trust.savedCertificateDer(id, "vpn.example", 5555))
        assertFalse(f.trustPreferences.durable.containsKey(CertificateProfileScope.key(id,
            CertificateEndpoint.of("vpn.example", 5555)) + "_der"))
    }

    @Test fun mismatchedOrMalformedStoredDerNeverEscapesAndIsNotCopied() {
        val f = Fixture()
        val id = f.profiles.importSaved(imported(), true)
        val key = CertificateProfileScope.key(id, CertificateEndpoint.of("vpn.example", 5555))
        f.trustPreferences.seed(key + "_der", Base64.getEncoder().encodeToString(certificate("future").encoded))
        assertNull(f.trust.savedCertificateDer(id, "vpn.example", 5555))
        val copied = f.profiles.copy(id, "Copy")
        assertNull(f.trust.savedCertificateDer(copied, "vpn.example", 5555))
        f.trustPreferences.seed(key + "_der", "invalid-base64!")
        assertNull(f.trust.savedCertificateDer(id, "vpn.example", 5555))
    }

    private fun imported(der: ByteArray = certificate().encoded) = ImportedSoftEtherProfile(
        name = "Imported", values = mapOf("HOME_HOSTNAME" to "vpn.example", "SSL_PORT" to "5555",
            "HOME_HUB" to "DEFAULT", "HOME_USERNAME" to "import-user", "HOME_PASSWORD" to "import-secret",
            "BACKEND_MODE" to "ROOT_NATIVE"), certificatePin = fingerprint(der), certificateDer = der)

    private fun certificate(name: String = "localhost"): X509Certificate =
        KeyStore.getInstance("PKCS12").apply {
            val fixture = checkNotNull(ProfileCertificateStoreTest::class.java.getResourceAsStream("/tls/$name.p12"))
            fixture.use { load(it, "test-only".toCharArray()) }
        }.getCertificate("test-server") as X509Certificate

    private fun fingerprint(der: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(der)
        .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) }

    private fun review(pin: String, expected: String) = CertificateReviewException(
        CertificateIdentity(pin, "CN=fixture", "CN=fixture", 0L, Long.MAX_VALUE, ""),
        expected, CertificateException("fixture review"))

    private fun hubApproval(port: Int = 5555) = HubCertificateApproval(
        CertificateEndpoint.of("vpn.example", port), "", review(firstPin, "").identity)

    private class MemoryPreferences : SharedPreferences {
        val values = linkedMapOf<String, Any>()
        val durable = linkedMapOf<String, Any>()
        var commitCount = 0
        var failAtCommit = -1
        fun seed(key: String, value: Any) { values[key] = value; durable[key] = value }
        override fun getAll(): MutableMap<String, *> = values.toMutableMap()
        override fun contains(key: String?): Boolean = values.containsKey(key)
        override fun getString(key: String?, defValue: String?) = values[key] as? String ?: defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            (values[key] as? Set<String>)?.toMutableSet() ?: defValues
        override fun getInt(key: String?, defValue: Int) = values[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long) = values[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float) = values[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean) = values[key] as? Boolean ?: defValue
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            private val changes = linkedMapOf<String, Any?>()
            private var clear = false
            private fun put(key: String?, value: Any?): SharedPreferences.Editor { changes[requireNotNull(key)] = value; return this }
            override fun putString(key: String?, value: String?) = put(key, value)
            override fun putStringSet(key: String?, values: MutableSet<String>?) = put(key, values?.toSet())
            override fun putBoolean(key: String?, value: Boolean) = put(key, value)
            override fun putInt(key: String?, value: Int) = put(key, value)
            override fun putLong(key: String?, value: Long) = put(key, value)
            override fun putFloat(key: String?, value: Float) = put(key, value)
            override fun remove(key: String?) = put(key, null)
            override fun clear(): SharedPreferences.Editor { clear = true; return this }
            override fun commit(): Boolean {
                commitCount++
                if (clear) values.clear()
                changes.forEach { (key, value) -> if (value == null) values.remove(key) else values[key] = value }
                if (commitCount == failAtCommit) return false
                durable.clear(); durable.putAll(values)
                return true
            }
            override fun apply() { commit() }
        }
    }
}
