package kittoku.mvc.profile

import android.content.SharedPreferences
import kittoku.mvc.tls.CertificateEndpoint
import kittoku.mvc.routing.TunDestinationConfiguration
import kittoku.mvc.routing.TunDestinationMode
import kittoku.mvc.routing.TunDestinationSettings
import org.junit.Assert.*
import org.junit.Test

class ProfileStoreTest {
    private class Trust : ProfileTrust {
        val pins = mutableMapOf<String, String>()
        var pending: String? = null
        var clearSucceeds = true
        var copySucceeds = true
        var deleteSucceeds = true
        var migrateSucceeds = true
        var installSucceeds = true
        var installCalls = 0
        var firstId = ""
        override fun migrate(firstId: String) {
            check(migrateSucceeds)
            this.firstId = firstId
        }
        override fun clearPending(): Boolean {
            if (clearSucceeds) pending = null
            return clearSucceeds
        }
        override fun copy(fromId: String, toId: String): Boolean {
            if (copySucceeds) pins[fromId]?.let { pins[toId] = it }
            return copySucceeds
        }
        override fun delete(id: String): Boolean { if (deleteSucceeds) pins.remove(id); return deleteSucceeds }
        override fun installImportedCertificate(profileId: String, endpoint: CertificateEndpoint, pin: String, der: ByteArray?): Boolean {
            installCalls++
            if (installSucceeds) pins[profileId] = pin
            return installSucceeds
        }
    }

    private class Fixture(legacy: Boolean = true) {
        val prefs = MemoryPreferences().apply {
            if (legacy) {
                seed("HOME_HOSTNAME", "first.example")
                seed("HOME_USERNAME", "first-user")
                seed("HOME_PASSWORD", "first-password-测试")
                seed("SSL_PORT", "5555")
                seed("BACKEND_MODE", "ROOT_NATIVE")
                seed("VPN_FORWARD_IPV6", false)
                seed("SSL_SUITES", setOf("suite-a", "suite-b"))
            }
            seed("UI_THEME", "DARK")
            seed("SHOW_NOTIFICATION_TRAFFIC", true)
        }
        val trust = Trust()
        private var next = 0
        val store = ProfileStore(prefs, trust) { "profile-${++next}" }
        fun activeId() = requireNotNull(store.ensureInitialized())
        fun activation() = requireNotNull(prefs.getString(ProfileStore.ACTIVATION_KEY, null))
        fun saveDestination(config: TunDestinationConfiguration) =
            TunDestinationSettings.saveForProfile(store, config, activeId(), activation())
    }

    @Test fun freshRegistryStaysEmptyUntilExplicitCreationAndReloadsAfterLastDelete() {
        val f = Fixture(legacy = false)
        val empty = ProfileUiState(null, emptyList(), false)
        assertEquals(empty, f.store.state())
        assertFalse(f.prefs.contains(ProfileStore.FIRST_ID_KEY))
        assertFalse(f.prefs.contains(ProfileStore.ACTIVATION_KEY))
        assertEquals(empty, ProfileStore(f.prefs, f.trust).state())

        val created = f.store.createSaved("First profile")
        assertEquals(created, f.store.state().activeId)
        assertEquals(TunDestinationMode.ALL, TunDestinationSettings.read(f.prefs)?.mode)
        assertEquals("443", f.prefs.getString("SSL_PORT", null))
        assertEquals("", f.prefs.getString("HOME_HUB", null))
        f.prefs.seed("HOME_PASSWORD", "unsaved-draft")
        f.prefs.seed(ProfileConnectionRequest.NONCE_KEY, "stale-request")
        f.trust.pins[created] = "certificate"
        f.store.delete(created)

        assertFalse(f.prefs.contains("HOME_PASSWORD"))
        assertFalse(f.prefs.contains(ProfileConnectionRequest.NONCE_KEY))
        assertFalse(f.prefs.contains(ProfileStore.ACTIVATION_KEY))
        assertNull(f.trust.pins[created])
        assertEquals("DARK", f.prefs.getString("UI_THEME", null))
        f.prefs.restore()
        assertEquals(empty, ProfileStore(f.prefs, f.trust).state())
        assertTrue(ProfileConnectionRequest.reserveStop(f.prefs) > 0)
        assertEquals(empty, f.store.state())

        val recreated = f.store.createSaved("Replacement")
        assertNotEquals(created, recreated)
        assertEquals(recreated, f.store.state().activeId)
        assertFalse(f.prefs.contains("HOME_PASSWORD"))
    }

    @Test fun migratesTheExistingConnectionWithoutChangingCredentialsOrGlobals() {
        val f = Fixture()
        val old = f.prefs.values.toMap()
        val state = f.store.state()
        assertEquals("profile-1", state.activeId)
        assertEquals("Default profile", state.profiles.single().name)
        assertFalse(state.hasUnsavedChanges)
        old.forEach { (key, value) -> assertEquals(value, f.prefs.values[key]) }
        assertEquals(state.activeId, f.trust.firstId)
        assertEquals(state.activeId, f.prefs.durable[ProfileStore.FIRST_ID_KEY])
    }

    @Test fun savesTwoIndependentPasswordsAndTypedConnectionSettingsAcrossRestarts() {
        val f = Fixture()
        val first = f.activeId()
        f.store.create("Second", true)
        assertFalse(f.prefs.contains("HOME_PASSWORD"))
        assertFalse(f.prefs.contains("SSL_SUITES"))
        f.prefs.edit().putString("HOME_HOSTNAME", "second.example").putString("HOME_PASSWORD", "second-secret")
            .putBoolean("VPN_FORWARD_IPV6", true).putStringSet("SSL_SUITES", setOf("suite-c")).commit()
        f.store.saveCurrent()
        val second = f.activeId()
        f.store.select(first, false)
        assertEquals("first-password-测试", f.prefs.getString("HOME_PASSWORD", null))
        assertEquals(setOf("suite-a", "suite-b"), f.prefs.getStringSet("SSL_SUITES", null))
        assertFalse(f.prefs.getBoolean("VPN_FORWARD_IPV6", true))
        f.store.select(second, false)
        f.prefs.restore()
        val restarted = ProfileStore(f.prefs, f.trust)
        assertEquals(second, restarted.state().activeId)
        assertEquals("second-secret", f.prefs.getString("HOME_PASSWORD", null))
        assertEquals(setOf("suite-c"), f.prefs.getStringSet("SSL_SUITES", null))
        assertTrue(f.prefs.getBoolean("VPN_FORWARD_IPV6", false))
        assertEquals("DARK", f.prefs.getString("UI_THEME", null))
        assertTrue(f.prefs.getBoolean("SHOW_NOTIFICATION_TRAFFIC", false))
    }

    @Test fun tunIpv6IsOptInPerProfileAndIndependentOfNativeIpv6() {
        val f = Fixture()
        val first = f.activeId()
        assertFalse(f.prefs.contains("TUN_FORWARD_IPV6"))
        assertFalse(f.prefs.getBoolean("TUN_FORWARD_IPV6", false))
        f.prefs.edit().putBoolean("TUN_FORWARD_IPV6", true).commit()
        f.store.saveCurrent()

        f.store.create("Second", true)
        val second = f.activeId()
        assertFalse(f.prefs.contains("TUN_FORWARD_IPV6"))
        f.prefs.edit().putBoolean("TUN_FORWARD_IPV6", false).putBoolean("VPN_FORWARD_IPV6", true).commit()
        f.store.saveCurrent()

        f.store.select(first, false)
        assertTrue(f.prefs.getBoolean("TUN_FORWARD_IPV6", false))
        assertFalse(f.prefs.getBoolean("VPN_FORWARD_IPV6", true))
        f.prefs.restore()
        val restarted = ProfileStore(f.prefs, f.trust)
        assertEquals(first, restarted.state().activeId)
        assertTrue(f.prefs.getBoolean("TUN_FORWARD_IPV6", false))
        restarted.select(second, false)
        assertFalse(f.prefs.getBoolean("TUN_FORWARD_IPV6", true))
        assertTrue(f.prefs.getBoolean("VPN_FORWARD_IPV6", false))
    }

    @Test fun destinationDraftDoesNotConvertLegacyAndUiCreatedProfileStartsWithAll() {
        val f = Fixture()
        val active = f.activeId()
        f.prefs.seed("LAN_ROUTES", "10.0.0.0/8")
        val before = f.prefs.values.toMap()
        assertNull(TunDestinationSettings.read(f.prefs))
        val draft = TunDestinationSettings.draft(f.prefs, "2001:db8::/32\nexample.test")
        assertEquals(TunDestinationMode.ALL, draft.mode)
        assertEquals("10.0.0.0/8", draft.includeRules)
        assertEquals("2001:db8::/32\nexample.test", draft.excludeRules)
        assertEquals(before, f.prefs.values)

        val created = f.store.createSaved("Modern")
        assertEquals("ALL", f.store.readForEdit(created).values[TunDestinationSettings.MODE_KEY])
        assertEquals(active, f.store.state().activeId)
        assertNull(TunDestinationSettings.read(f.prefs))
        val official = f.store.importSaved(imported(), false)
        assertEquals("ALL", f.store.readForEdit(official).values[TunDestinationSettings.MODE_KEY])
        val legacy = f.store.importSaved(imported(values = mapOf("ROUTE_MODE" to "LAN",
            "LAN_ROUTES" to "10.0.0.0/8")), false)
        assertEquals(mapOf("ROUTE_MODE" to "LAN", "LAN_ROUTES" to "10.0.0.0/8"), f.store.readForEdit(legacy).values)
        val modern = f.store.importSaved(imported(values = mapOf(TunDestinationSettings.MODE_KEY to "INCLUDE",
            TunDestinationSettings.INCLUDE_KEY to "192.0.2.1")), false)
        assertEquals("INCLUDE", f.store.readForEdit(modern).values[TunDestinationSettings.MODE_KEY])
        val copied = f.store.copy(active, "Legacy copy")
        assertFalse(f.store.readForEdit(copied).values.containsKey(TunDestinationSettings.MODE_KEY))
    }

    @Test fun destinationListsRemainSeparateAcrossModeSwitchProfileCopyAndRestart() {
        val f = Fixture()
        val first = f.activeId()
        val include = "10.0.0.0/8\n2001:db8::/32\nexample.test"
        val exclude = "192.0.2.1"
        assertTrue(f.saveDestination(
            TunDestinationConfiguration(TunDestinationMode.INCLUDE, include, exclude)))
        val copied = f.store.copy(first, "Modern copy")
        assertEquals(include, f.store.readForEdit(copied).values[TunDestinationSettings.INCLUDE_KEY])
        f.store.select(copied, false)
        assertTrue(f.saveDestination(
            TunDestinationConfiguration(TunDestinationMode.EXCLUDE, include, exclude)))
        f.store.select(first, false)
        f.prefs.restore()
        val restarted = ProfileStore(f.prefs, f.trust)
        assertEquals(first, restarted.ensureInitialized())
        assertEquals(TunDestinationConfiguration(TunDestinationMode.INCLUDE, include, exclude),
            TunDestinationSettings.read(f.prefs))
        restarted.select(copied, false)
        assertEquals(TunDestinationConfiguration(TunDestinationMode.EXCLUDE, include, exclude),
            TunDestinationSettings.read(f.prefs))
    }

    @Test fun destinationCommitFailureRestoresOnlyOwnedFieldsInMemoryAndOnRetry() {
        val f = Fixture()
        f.store.ensureInitialized()
        f.prefs.seed(TunDestinationSettings.INCLUDE_KEY, "old inactive draft")
        val before = f.prefs.values.toMap()
        val durable = f.prefs.durable.toMap()
        val config = TunDestinationConfiguration(TunDestinationMode.EXCLUDE, "invalid dormant URL://", "192.0.2.1")
        f.prefs.failCommits = true // This fake still publishes the failed edit into memory.
        assertThrows(IllegalStateException::class.java) { f.saveDestination(config) }
        assertEquals(before, f.prefs.values)
        assertEquals(durable, f.prefs.durable)
        assertNull(TunDestinationSettings.read(f.prefs))
        f.prefs.failCommits = false
        assertTrue(f.saveDestination(config))
        assertEquals(config, TunDestinationSettings.read(f.prefs))
    }

    @Test fun destinationSaveRejectsWrongIdentityButCanSaveForTheNextConnectionWhileActive() {
        val f = Fixture()
        val id = f.activeId()
        val activation = requireNotNull(f.prefs.getString(ProfileStore.ACTIVATION_KEY, null))
        val config = TunDestinationConfiguration(TunDestinationMode.ALL, "not a rule", "also invalid://")
        val before = f.prefs.values.toMap()
        assertFalse(TunDestinationSettings.saveForProfile(f.store, config, "another-profile", activation))
        assertFalse(TunDestinationSettings.saveForProfile(f.store, config, id, "old-activation"))
        assertEquals(before, f.prefs.values)
        f.prefs.seed("HOME_CONNECTOR", true)
        assertTrue(TunDestinationSettings.saveForProfile(f.store, config, id, activation))
        assertTrue(f.prefs.getBoolean("HOME_CONNECTOR", false))
        assertEquals(id, f.prefs.getString(ProfileStore.ACTIVE_ID_KEY, null))
        assertEquals(activation, f.prefs.getString(ProfileStore.ACTIVATION_KEY, null))
        assertEquals(config, TunDestinationSettings.read(f.prefs))
        assertFalse(f.store.state().hasUnsavedChanges)
        assertEquals("", config.activeRules)
    }

    @Test fun destinationValidationRejectsActiveInvalidAndEmptyIncludeWithoutChangingPrefs() {
        val f = Fixture()
        f.store.ensureInitialized()
        val before = f.prefs.values.toMap()
        assertThrows(IllegalArgumentException::class.java) {
            f.saveDestination(TunDestinationConfiguration(TunDestinationMode.INCLUDE, " \n", ""))
        }
        assertThrows(IllegalArgumentException::class.java) {
            f.saveDestination(TunDestinationConfiguration(TunDestinationMode.EXCLUDE, "", "https://example.test"))
        }
        assertEquals(before, f.prefs.values)
        assertTrue(f.saveDestination(TunDestinationConfiguration(TunDestinationMode.EXCLUDE, "invalid://", "")))
        f.prefs.seed(TunDestinationSettings.MODE_KEY, "UNKNOWN")
        assertThrows(IllegalArgumentException::class.java) { TunDestinationSettings.read(f.prefs) }
    }

    @Test fun writesOfImplicitDefaultsDoNotMakeANewProfileDirty() {
        val f = Fixture(legacy = false)
        f.store.createSaved("New")
        assertFalse(f.store.state().hasUnsavedChanges)

        f.prefs.edit().putString("BACKEND_MODE", "TUN")
            .putString("AUTH_PASSWORD_ENCODING", "UTF-8")
            .putBoolean("VPN_FORWARD_IPV6", false)
            .putBoolean("TUN_FORWARD_IPV6", false)
            .putBoolean("NATIVE_MANAGEMENT_ONLY", false)
            .putBoolean("UDP_ENABLE_ACCELERATION", false).commit()

        assertFalse(f.store.state().hasUnsavedChanges)
        f.prefs.edit().putBoolean("VPN_FORWARD_IPV6", true).commit()
        assertTrue(f.store.state().hasUnsavedChanges)
        f.prefs.edit().putBoolean("VPN_FORWARD_IPV6", false).commit()
        assertFalse(f.store.state().hasUnsavedChanges)
        f.prefs.edit().putString("BACKEND_MODE", "ROOT_NATIVE").commit()
        assertTrue(f.store.state().hasUnsavedChanges)
        f.store.saveCurrent()
        assertFalse(f.store.state().hasUnsavedChanges)
    }

    @Test fun upgradeClearsOldWorkingOnlyTapDefaultButKeepsLaterOptIn() {
        val f = Fixture(legacy = false)
        val id = "old-profile"
        f.prefs.seed(ProfileStore.REGISTRY_KEY, ProfileCodec.encode(listOf(StoredProfile(id, "Old", emptyMap()))))
        f.prefs.seed(ProfileStore.ACTIVE_ID_KEY, id)
        f.prefs.seed(ProfileStore.FIRST_ID_KEY, id)
        f.prefs.seed("VPN_FORWARD_IPV6", true)

        assertFalse(f.store.state().hasUnsavedChanges)
        assertFalse(f.prefs.contains("VPN_FORWARD_IPV6"))
        f.prefs.edit().putBoolean("VPN_FORWARD_IPV6", true).commit()
        f.prefs.restore()
        val reloaded = ProfileStore(f.prefs, f.trust)
        assertTrue(reloaded.state().hasUnsavedChanges)
        assertTrue(f.prefs.getBoolean("VPN_FORWARD_IPV6", false))
    }

    @Test fun upgradeSavesPriorSettingsEditsWithoutSavingProfileEditorDrafts() {
        for (savedValue in listOf(false, true)) {
            val f = Fixture(legacy = false)
            val id = "old-profile"
            val saved = mapOf("VPN_FORWARD_IPV6" to savedValue, "TUN_FORWARD_IPV6" to true,
                "HOME_USERNAME" to "saved-user")
            f.prefs.seed(ProfileStore.REGISTRY_KEY, ProfileCodec.encode(listOf(StoredProfile(id, "Old", saved))))
            f.prefs.seed(ProfileStore.ACTIVE_ID_KEY, id)
            f.prefs.seed(ProfileStore.FIRST_ID_KEY, id)
            f.prefs.seed("VPN_FORWARD_IPV6", true)
            f.prefs.seed("TUN_FORWARD_IPV6", true)
            f.prefs.seed("HOME_USERNAME", "legacy-draft-user")

            assertTrue(f.store.state().hasUnsavedChanges)
            assertEquals("legacy-draft-user", f.prefs.getString("HOME_USERNAME", null))
            assertTrue(f.prefs.getBoolean("VPN_FORWARD_IPV6", false))
            assertTrue(f.prefs.getBoolean("TUN_FORWARD_IPV6", false))
            val registry = ProfileCodec.decode(requireNotNull(f.prefs.getString(ProfileStore.REGISTRY_KEY, null)))
            assertEquals(true, registry.single().values["VPN_FORWARD_IPV6"])
            assertEquals("saved-user", registry.single().values["HOME_USERNAME"])
            assertFalse(f.activation().isBlank())
        }
    }

    @Test fun settingsChangesAreSavedToTheActiveProfileWithoutSavingAnExistingDraft() {
        val f = Fixture()
        val first = f.activeId()
        val activation = f.activation()
        val originalPassword = f.prefs.getString("HOME_PASSWORD", null)
        f.prefs.edit().putString("HOME_PASSWORD", "legacy-draft").commit()
        f.prefs.seed("HOME_CONNECTOR", true)
        val settings = mapOf("BACKEND_MODE" to "TUN", "AUTH_PASSWORD_ENCODING" to "GBK", "TUN_FORWARD_IPV6" to true)
        assertTrue(f.store.saveSettings(first, activation, settings))
        assertTrue(f.store.state().hasUnsavedChanges)
        assertEquals("legacy-draft", f.prefs.getString("HOME_PASSWORD", null))
        f.prefs.seed("HOME_CONNECTOR", false)
        f.store.create("Second", false)
        assertFalse(f.store.saveSettings(first, activation, settings))
        f.store.select(first, false)
        assertFalse(f.store.state().hasUnsavedChanges)
        assertEquals(originalPassword, f.prefs.getString("HOME_PASSWORD", null))
        assertEquals("TUN", f.prefs.getString("BACKEND_MODE", null))
        assertEquals("GBK", f.prefs.getString("AUTH_PASSWORD_ENCODING", null))
        assertTrue(f.prefs.getBoolean("TUN_FORWARD_IPV6", false))
    }

    @Test fun automaticTapUpgradeDoesNotLeaveAnUnsavedChange() {
        val f = Fixture()
        f.prefs.seed("BACKEND_MODE", "ROOT_TAP")
        f.store.ensureInitialized()
        f.prefs.edit().putString("BACKEND_MODE", "ROOT_NATIVE").commit()
        assertFalse(f.store.state().hasUnsavedChanges)

        f.prefs.edit().putString(TunDestinationSettings.MODE_KEY, TunDestinationMode.ALL.name).commit()
        assertTrue(f.store.state().hasUnsavedChanges)
    }

    @Test fun dirtyDraftSurvivesRestartAndCanBeSavedOnSwitchOrExplicitlyDiscarded() {
        val f = Fixture()
        val first = f.activeId()
        f.store.create("Second", true)
        val second = f.activeId()
        f.store.select(first, false)
        f.prefs.edit().putString("HOME_PASSWORD", "saved-on-switch").commit()
        assertTrue(ProfileStore(f.prefs, f.trust).state().hasUnsavedChanges)
        f.store.select(second, true)
        f.store.select(first, false)
        assertEquals("saved-on-switch", f.prefs.getString("HOME_PASSWORD", null))
        f.prefs.edit().putString("HOME_PASSWORD", "discard-me").commit()
        f.store.select(second, false)
        f.store.select(first, false)
        assertEquals("saved-on-switch", f.prefs.getString("HOME_PASSWORD", null))
    }

    @Test fun copiedProfileCarriesItsOwnDraftAndTrustAndLeavesOriginalSaveUntouched() {
        val f = Fixture()
        val first = f.activeId()
        f.trust.pins[first] = "certificate-a"
        f.prefs.edit().putString("HOME_PASSWORD", "copied-draft").commit()
        f.store.copyCurrent("Copy")
        val copy = f.activeId()
        assertEquals("certificate-a", f.trust.pins[copy])
        assertEquals("copied-draft", f.prefs.getString("HOME_PASSWORD", null))
        f.trust.pins[copy] = "certificate-b"
        assertEquals("certificate-a", f.trust.pins[first])
        f.store.select(first, false)
        assertEquals("first-password-测试", f.prefs.getString("HOME_PASSWORD", null))
    }

    @Test fun newProfileStartsWithoutTrustAndEverySwitchCancelsPendingAndPermissionNonce() {
        val f = Fixture()
        val first = f.activeId()
        f.trust.pins[first] = "certificate-a"
        f.trust.pending = "old-approval"
        f.prefs.seed("QUICK_CONNECT_REQUEST_ID", "old-request")
        f.prefs.seed("VPN_PERMISSION_PROFILE_ID", first)
        f.store.create("Empty", false)
        assertNull(f.trust.pins[f.store.state().activeId])
        assertNull(f.trust.pending)
        assertFalse(f.prefs.contains("QUICK_CONNECT_REQUEST_ID"))
        assertFalse(f.prefs.contains("VPN_PERMISSION_PROFILE_ID"))
        f.store.select(first, false)
        assertNull(f.trust.pending)
    }

    @Test fun blocksSwitchCreateCopyDeleteWhileConnectingConnectedOrRetrying() {
        val f = Fixture()
        val first = f.activeId()
        f.store.create("Second", false)
        f.prefs.seed("HOME_CONNECTOR", true)
        for (action in listOf<() -> Unit>({ f.store.select(first, true) }, { f.store.create("No", false) },
            { f.store.copyCurrent("No") }, { f.store.deleteCurrent() })) {
            assertThrows(IllegalStateException::class.java, action)
        }
        // Saving/renaming do not change the session identity.
        f.store.saveCurrent()
        f.store.renameCurrent("Renamed")
        assertEquals("Renamed", f.store.state().profiles.last().name)
        assertNotEquals(first, f.store.state().activeId)
    }

    @Test fun renameDoesNotSaveOrDiscardADirtyPasswordAndNameValidationIsBounded() {
        val f = Fixture()
        f.store.state()
        f.prefs.edit().putString("HOME_PASSWORD", "draft").commit()
        f.store.renameCurrent("  New name  ")
        assertEquals("New name", f.store.state().profiles.single().name)
        assertTrue(f.store.state().hasUnsavedChanges)
        for (name in listOf("", " ", "bad\nname", "x".repeat(65))) {
            assertThrows(IllegalArgumentException::class.java) { f.store.renameCurrent(name) }
        }
    }

    @Test fun deletingAProfileRemovesOnlyItsTrust() {
        val f = Fixture()
        val first = f.activeId()
        f.trust.pins[first] = "a"
        f.store.copyCurrent("Copy")
        val copy = f.activeId()
        f.store.deleteCurrent()
        assertEquals(first, f.store.state().activeId)
        assertEquals("a", f.trust.pins[first])
        assertNull(f.trust.pins[copy])
    }

    @Test fun failedInitialCommitNeverMigratesTrustAndCanRetryWithoutLosingTheLegacyConnection() {
        val f = Fixture()
        f.prefs.failCommits = true
        assertThrows(IllegalStateException::class.java) { f.store.state() }
        assertFalse(f.prefs.contains(ProfileStore.REGISTRY_KEY))
        assertEquals("", f.trust.firstId)
        assertEquals("first-password-测试", f.prefs.getString("HOME_PASSWORD", null))
        f.prefs.failCommits = false
        assertFalse(f.store.state().hasUnsavedChanges)
        assertEquals("first-password-测试", f.prefs.durable["HOME_PASSWORD"])
    }

    @Test fun failedSwitchRestoresBothRegistryAndWorkingCopyEvenAfterMemoryWasPublished() {
        val f = Fixture()
        val first = f.activeId()
        f.store.create("Second", true)
        val before = f.prefs.values.toMap()
        f.prefs.failCommits = true
        assertThrows(IllegalStateException::class.java) { f.store.select(first, false) }
        assertEquals(before, f.prefs.values)
        f.prefs.failCommits = false
        f.store.select(first, false)
        assertEquals("first-password-测试", f.prefs.durable["HOME_PASSWORD"])
        assertEquals(first, f.prefs.durable[ProfileStore.ACTIVE_ID_KEY])
    }

    @Test fun failedTrustMigrationOrPendingClearCannotPublishAnotherProfile() {
        val f = Fixture()
        f.trust.migrateSucceeds = false
        assertThrows(IllegalStateException::class.java) { f.store.state() }
        assertTrue(f.prefs.durable.containsKey(ProfileStore.REGISTRY_KEY))
        f.trust.migrateSucceeds = true
        val before = f.store.state()
        f.trust.clearSucceeds = false
        assertThrows(IllegalStateException::class.java) { f.store.create("No", false) }
        assertEquals(before, f.store.state())
    }

    @Test fun corruptOrIncompleteRegistryFailsClosedAndDoesNotOverwriteCredentials() {
        val f = Fixture()
        f.prefs.seed(ProfileStore.REGISTRY_KEY, "corrupt")
        assertThrows(IllegalStateException::class.java) { f.store.state() }
        assertEquals("first-password-测试", f.prefs.getString("HOME_PASSWORD", null))
        assertEquals("corrupt", f.prefs.getString(ProfileStore.REGISTRY_KEY, null))
    }

    @Test fun codecRoundTripsAllTypesAndRejectsTruncationTrailingDataAndDuplicateIds() {
        val values = mapOf<String, Any>("HOME_PASSWORD" to "私密\u0000value", "VPN_FORWARD_IPV6" to true,
            "SSL_SUITES" to setOf("b", "a"))
        val profiles = listOf(StoredProfile("a", "Profile", values))
        val encoded = ProfileCodec.encode(profiles)
        assertEquals(profiles, ProfileCodec.decode(encoded))
        val bytes = java.util.Base64.getDecoder().decode(encoded)
        for (length in listOf(0, 4, bytes.size - 1)) {
            assertThrows(Exception::class.java) { ProfileCodec.decode(java.util.Base64.getEncoder().encodeToString(bytes.copyOf(length))) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProfileCodec.decode(java.util.Base64.getEncoder().encodeToString(bytes + byteArrayOf(0)))
        }
        assertThrows(IllegalArgumentException::class.java) { ProfileCodec.encode(profiles + profiles) }
        assertFalse(profiles.single().toString().contains("私密"))
    }

    @Test fun oversizedPasswordCannotLeakItsHeadOrTailIntoADiagnosticException() {
        val password = "PRIVATE_HEAD" + "密".repeat(22000) + "PRIVATE_TAIL"
        val error = assertThrows(IllegalArgumentException::class.java) {
            ProfileCodec.encode(listOf(StoredProfile("a", "Name", mapOf("HOME_PASSWORD" to password))))
        }
        assertFalse(error.stackTraceToString().contains("PRIVATE_HEAD"))
        assertFalse(error.stackTraceToString().contains("PRIVATE_TAIL"))
    }

    @Test fun encodeRejectsASetThatWouldExceedItsOwnDecoderLimit() {
        assertThrows(IllegalArgumentException::class.java) {
            ProfileCodec.encode(listOf(StoredProfile("a", "Name", mapOf("SSL_SUITES" to
                (1..1001).map { "suite-$it" }.toSet()))))
        }
    }

    @Test fun queuedServiceStartCannotFollowAProfileSwitchOrSurviveANewerRequest() {
        val f = Fixture()
        val first = f.activeId()
        val old = ProfileConnectionRequest.reserve(f.prefs, first)
        assertThrows(IllegalStateException::class.java) { f.store.create("No", false) }
        f.prefs.edit().putBoolean("HOME_CONNECTOR", false).commit()
        f.store.create("Second", false)
        f.store.select(first, false)
        val current = ProfileConnectionRequest.reserve(f.prefs, first)
        assertFalse(ProfileConnectionRequest.consume(f.prefs, old.profileId, old.nonce))
        assertFalse(ProfileConnectionRequest.cancel(f.prefs, old))
        assertTrue(f.prefs.getBoolean("HOME_CONNECTOR", false))
        assertTrue(ProfileConnectionRequest.consume(f.prefs, current.profileId, current.nonce))
        assertFalse(ProfileConnectionRequest.consume(f.prefs, current.profileId, current.nonce))
    }

    @Test fun failedForegroundLaunchCanReleaseOnlyItsOwnReservation() {
        val f = Fixture()
        val first = f.activeId()
        val request = ProfileConnectionRequest.reserve(f.prefs, first)
        assertTrue(ProfileConnectionRequest.cancel(f.prefs, request))
        assertFalse(f.prefs.getBoolean("HOME_CONNECTOR", true))
        assertFalse(f.prefs.contains(ProfileConnectionRequest.NONCE_KEY))
        val newer = ProfileConnectionRequest.reserve(f.prefs, first)
        assertFalse(ProfileConnectionRequest.cancel(f.prefs, request))
        assertTrue(ProfileConnectionRequest.consume(f.prefs, newer.profileId, newer.nonce))
    }

    @Test fun switchingBackToTheSameProfileCannotReviveAnOldEditorActivation() {
        val f = Fixture()
        val first = f.activeId()
        val activation = f.prefs.getString(ProfileStore.ACTIVATION_KEY, null)
        assertNotNull(activation)
        f.store.saveCurrent()
        f.store.renameCurrent("Renamed")
        assertEquals(activation, f.prefs.getString(ProfileStore.ACTIVATION_KEY, null))
        f.store.create("Second", false)
        f.store.select(first, false)
        assertNotEquals(activation, f.prefs.getString(ProfileStore.ACTIVATION_KEY, null))
    }

    @Test fun immediateStopInvalidatesAnOldConnectEvenWhenAnotherPermissionRequestIsPending() {
        val f = Fixture()
        val first = f.activeId()
        val old = ProfileConnectionRequest.reserve(f.prefs, first)
        val stop = ProfileConnectionRequest.reserveStop(f.prefs)
        f.prefs.edit().putBoolean("HOME_CONNECTOR", true).putString("VPN_PERMISSION_REQUEST_ID", "new-permission").commit()
        assertFalse(ProfileConnectionRequest.consume(f.prefs, old.profileId, old.nonce, old.sequence))
        assertTrue(ProfileConnectionRequest.stopAffectsSession(old.sequence, stop))
        assertTrue(f.prefs.getBoolean("HOME_CONNECTOR", false))
        val newer = ProfileConnectionRequest.reserve(f.prefs, first)
        assertTrue(ProfileConnectionRequest.consume(f.prefs, newer.profileId, newer.nonce, newer.sequence))
        assertFalse(ProfileConnectionRequest.stopAffectsSession(newer.sequence, stop))
    }

    @Test fun editorSnapshotReadsActiveWorkingDraftAndInactiveSavedValuesWithoutSelecting() {
        val f = Fixture()
        val first = f.activeId()
        val inactive = f.store.createSaved("Saved only")
        val before = f.prefs.values.toMap()
        f.prefs.edit().putString("HOME_PASSWORD", "active-draft").commit()
        assertEquals("active-draft", f.store.readForEdit(first).values["HOME_PASSWORD"])
        assertEquals(mapOf("SSL_PORT" to "443", "HOME_HUB" to "", TunDestinationSettings.MODE_KEY to "ALL",
            TunDestinationSettings.INCLUDE_KEY to "", TunDestinationSettings.EXCLUDE_KEY to ""),
            f.store.readForEdit(inactive).values)
        assertEquals(first, f.store.state().activeId)
        assertEquals(before[ProfileStore.ACTIVATION_KEY], f.prefs.values[ProfileStore.ACTIVATION_KEY])
        assertTrue(f.store.state().hasUnsavedChanges)
    }

    @Test fun editorSnapshotOwnsItsSetAndCannotMutateTheWorkingPreferences() {
        val f = Fixture()
        val id = f.activeId()
        val snapshot = f.store.readForEdit(id)
        @Suppress("UNCHECKED_CAST")
        (snapshot.values["SSL_SUITES"] as MutableSet<String>).add("snapshot-only")
        assertEquals(setOf("suite-a", "suite-b"), f.prefs.getStringSet("SSL_SUITES", null))
        assertEquals(setOf("suite-a", "suite-b"), f.store.readForEdit(id).values["SSL_SUITES"])
        assertFalse(snapshot.toString().contains("first-password"))
    }

    @Test fun savingAnInactiveEditorWhileConnectedPreservesCurrentDraftSessionAndPendingApproval() {
        val f = Fixture()
        val first = f.activeId()
        val inactive = f.store.createSaved("Inactive")
        val expected = f.store.readForEdit(inactive)
        f.prefs.seed("HOME_PASSWORD", "unsaved-current-draft")
        f.prefs.seed("HOME_CONNECTOR", true)
        f.prefs.seed("HOME_STATUS", "connected")
        f.prefs.seed("VPN_PERMISSION_PROFILE_ID", first)
        f.trust.pending = "current-review"
        val before = f.prefs.values.toMap()
        val edited = expected.values + mapOf("HOME_HOSTNAME" to "inactive.example", "HOME_PASSWORD" to "  exact secret  ",
            "SSL_SUITES" to setOf("new-suite"), "VPN_FORWARD_IPV6" to true)
        f.store.saveProfile(expected, "  Edited inactive  ", edited)
        assertSessionUnchanged(f, before)
        assertEquals("current-review", f.trust.pending)
        assertEquals("Edited inactive", f.store.readForEdit(inactive).name)
        assertEquals("  exact secret  ", f.store.readForEdit(inactive).values["HOME_PASSWORD"])
        assertTrue(f.store.state().hasUnsavedChanges)
    }

    @Test fun savingTheActiveEditorCommitsItsRegistryAndWorkingCopyWithoutChangingActivation() {
        val f = Fixture()
        val active = f.activeId()
        val expected = f.store.readForEdit(active)
        val activation = f.prefs.values[ProfileStore.ACTIVATION_KEY]
        f.trust.pending = "same-profile-review"
        val edited = expected.values + mapOf("HOME_HOSTNAME" to "edited.example", "HOME_PASSWORD" to "  secret-新  ")
        f.store.saveProfile(expected, "Edited", edited)
        assertEquals(edited, f.store.readForEdit(active).values)
        assertEquals("  secret-新  ", f.prefs.durable["HOME_PASSWORD"])
        assertEquals(activation, f.prefs.values[ProfileStore.ACTIVATION_KEY])
        assertEquals("same-profile-review", f.trust.pending)
        assertFalse(f.store.state().hasUnsavedChanges)
        f.prefs.restore()
        assertEquals(edited, ProfileStore(f.prefs, f.trust).readForEdit(active).values)
    }

    @Test fun savingAnActiveOrNewlySelectedTargetFailsWhileItsSessionIsBusy() {
        val f = Fixture()
        val first = f.activeId()
        val inactive = f.store.createSaved("Later active")
        val firstSnapshot = f.store.readForEdit(first)
        val targetSnapshot = f.store.readForEdit(inactive)
        f.prefs.seed("HOME_CONNECTOR", true)
        val before = f.prefs.values.toMap()
        assertThrows(IllegalStateException::class.java) { f.store.saveProfile(firstSnapshot, "No", firstSnapshot.values) }
        assertEquals(before, f.prefs.values)
        f.prefs.seed("HOME_CONNECTOR", false)
        f.store.select(inactive, false)
        f.prefs.seed("HOME_CONNECTOR", true)
        assertThrows(IllegalStateException::class.java) { f.store.saveProfile(targetSnapshot, "No", targetSnapshot.values) }
    }

    @Test fun savingRejectsAChangedNameOrAnyChangedFieldRatherThanOverwritingNewerEdits() {
        val f = Fixture()
        val active = f.activeId()
        val inactive = f.store.createSaved("Original")
        val old = f.store.readForEdit(inactive)
        f.store.rename(inactive, "Newer name")
        assertThrows(IllegalStateException::class.java) { f.store.saveProfile(old, "Stale", old.values) }
        val current = f.store.readForEdit(inactive)
        f.store.saveProfile(current, current.name, current.values + ("HOME_PASSWORD" to "newer-secret"))
        assertThrows(IllegalStateException::class.java) { f.store.saveProfile(current, "Stale", current.values) }
        val activeSnapshot = f.store.readForEdit(active)
        f.prefs.edit().putBoolean("VPN_FORWARD_IPV6", true).commit()
        assertThrows(IllegalStateException::class.java) { f.store.saveProfile(activeSnapshot, "Stale", activeSnapshot.values) }
        assertEquals("newer-secret", f.store.readForEdit(inactive).values["HOME_PASSWORD"])
    }

    @Test fun targetedSaveRejectsUnknownKeysWrongTypesAndInvalidNamesWithoutExposingValues() {
        val f = Fixture()
        val active = f.activeId()
        val expected = f.store.readForEdit(active)
        val before = f.prefs.values.toMap()
        val privateValue = "PRIVATE_SECRET_VALUE"
        for (invalid in listOf<Map<String, Any>>(expected.values + ("HOME_CONNECTOR" to true),
            expected.values + ("UI_THEME" to privateValue), expected.values + ("HOME_PASSWORD" to true),
            expected.values + ("VPN_FORWARD_IPV6" to privateValue), expected.values + ("SSL_SUITES" to setOf(1)))) {
            val error = assertThrows(IllegalArgumentException::class.java) { f.store.saveProfile(expected, "Name", invalid) }
            assertFalse(error.stackTraceToString().contains(privateValue))
            assertEquals(before, f.prefs.values)
        }
        assertThrows(IllegalArgumentException::class.java) { f.store.saveProfile(expected, "bad\nname", expected.values) }
        assertEquals(before, f.prefs.values)
    }

    @Test fun saveCopiesSubmittedSetsSoLaterUiMutationsCannotChangeStoredConfiguration() {
        val f = Fixture()
        val active = f.activeId()
        val expected = f.store.readForEdit(active)
        val suites = linkedSetOf("one", "two")
        f.store.saveProfile(expected, expected.name, expected.values + ("SSL_SUITES" to suites))
        suites += "late-ui-mutation"
        assertEquals(setOf("one", "two"), f.prefs.getStringSet("SSL_SUITES", null))
        assertEquals(setOf("one", "two"), f.store.readForEdit(active).values["SSL_SUITES"])
    }

    @Test fun failedTargetedSavesRestoreThePriorRegistryAndWorkingDraftAndCanRetry() {
        for (targetActive in listOf(true, false)) {
            val f = Fixture()
            val active = f.activeId()
            val inactive = f.store.createSaved("Inactive")
            val expected = f.store.readForEdit(if (targetActive) active else inactive)
            val before = f.prefs.values.toMap()
            f.prefs.failCommits = true
            assertThrows(IllegalStateException::class.java) {
                f.store.saveProfile(expected, "Edited", expected.values + ("HOME_PASSWORD" to "retry-secret"))
            }
            assertEquals(before, f.prefs.values)
            f.prefs.failCommits = false
            f.store.saveProfile(expected, "Edited", expected.values + ("HOME_PASSWORD" to "retry-secret"))
            f.prefs.restore()
            assertEquals("retry-secret", f.store.readForEdit(expected.id).values["HOME_PASSWORD"])
        }
    }

    @Test fun targetedRenameWhileConnectedDoesNotSaveAnyProfileDraftOrChangeIdentity() {
        val f = Fixture()
        val active = f.activeId()
        val inactive = f.store.createSaved("Inactive")
        f.prefs.seed("HOME_PASSWORD", "dirty-active")
        f.prefs.seed("HOME_CONNECTOR", true)
        f.trust.pending = "approval"
        val before = f.prefs.values.toMap()
        f.store.rename(inactive, "  Inactive renamed  ")
        f.store.rename(active, "Active renamed")
        assertSessionUnchanged(f, before)
        assertEquals("Inactive renamed", f.store.readForEdit(inactive).name)
        assertEquals("Active renamed", f.store.readForEdit(active).name)
        assertTrue(f.store.state().hasUnsavedChanges)
        assertEquals("approval", f.trust.pending)
    }

    @Test fun createSavedWhileConnectedKeepsTheCurrentConnectionDraftAndTrust() {
        val f = Fixture()
        val active = f.activeId()
        f.trust.pins[active] = "active-certificate"
        f.trust.pending = "current-pending"
        f.prefs.seed("HOME_PASSWORD", "dirty")
        f.prefs.seed("HOME_CONNECTOR", true)
        val before = f.prefs.values.toMap()
        val id = f.store.createSaved("  New saved  ")
        assertSessionUnchanged(f, before)
        assertEquals("New saved", f.store.readForEdit(id).name)
        assertEquals(mapOf("SSL_PORT" to "443", "HOME_HUB" to "", TunDestinationSettings.MODE_KEY to "ALL",
            TunDestinationSettings.INCLUDE_KEY to "", TunDestinationSettings.EXCLUDE_KEY to ""),
            f.store.readForEdit(id).values)
        assertNull(f.trust.pins[id])
        assertEquals("current-pending", f.trust.pending)
        assertTrue(f.store.state().hasUnsavedChanges)
    }

    @Test fun targetedCopiesUseActiveDraftOrInactiveSavedValuesWithoutActivationOrPendingClear() {
        val f = Fixture()
        val active = f.activeId()
        val inactive = f.store.createSaved("Inactive")
        val inactiveSnapshot = f.store.readForEdit(inactive)
        f.store.saveProfile(inactiveSnapshot, "Inactive", inactiveSnapshot.values + ("HOME_PASSWORD" to "inactive-saved"))
        f.trust.pins[active] = "active-cert"; f.trust.pins[inactive] = "inactive-cert"
        f.trust.pending = "current-approval"
        f.prefs.seed("HOME_PASSWORD", "active-draft")
        f.prefs.seed("HOME_CONNECTOR", true)
        val before = f.prefs.values.toMap()
        val activeCopy = f.store.copy(active, "Active duplicate")
        val inactiveCopy = f.store.copy(inactive, "Inactive duplicate")
        assertSessionUnchanged(f, before)
        assertEquals("active-draft", f.store.readForEdit(activeCopy).values["HOME_PASSWORD"])
        assertEquals("inactive-saved", f.store.readForEdit(inactiveCopy).values["HOME_PASSWORD"])
        assertEquals("active-cert", f.trust.pins[activeCopy])
        assertEquals("inactive-cert", f.trust.pins[inactiveCopy])
        assertEquals("current-approval", f.trust.pending)
        f.trust.pins[activeCopy] = "independent-cert"
        assertEquals("active-cert", f.trust.pins[active])
        assertTrue(f.store.state().hasUnsavedChanges)
    }

    @Test fun targetedCopyCannotPublishWithoutTrustAndFailedRegistryWriteCleansItsUnusedScope() {
        val f = Fixture()
        val active = f.activeId()
        f.trust.pins[active] = "source-cert"
        val before = f.prefs.values.toMap()
        f.trust.copySucceeds = false
        assertThrows(IllegalStateException::class.java) { f.store.copy(active, "No") }
        assertEquals(before, f.prefs.values)
        f.trust.copySucceeds = true
        f.prefs.failCommits = true
        assertThrows(IllegalStateException::class.java) { f.store.copy(active, "No") }
        assertEquals(before, f.prefs.values)
        assertEquals(mapOf(active to "source-cert"), f.trust.pins)
        f.prefs.failCommits = false
        val copied = f.store.copy(active, "Retry")
        assertNotEquals(active, copied)
        assertEquals("source-cert", f.trust.pins[copied])
        assertEquals(active, f.store.state().activeId)
    }

    @Test fun deletingInactiveWhileConnectedPreservesCurrentSettingsStatusAndPendingTrust() {
        val f = Fixture()
        val active = f.activeId()
        val inactive = f.store.createSaved("Delete me")
        f.trust.pins[active] = "current-cert"; f.trust.pins[inactive] = "delete-cert"
        f.trust.pending = "current-approval"
        f.prefs.seed("HOME_CONNECTOR", true)
        f.prefs.seed("HOME_STATUS", "connected")
        val before = f.prefs.values.toMap()
        f.store.delete(inactive)
        assertSessionUnchanged(f, before)
        assertEquals(listOf(active), f.store.state().profiles.map { it.id })
        assertEquals("current-cert", f.trust.pins[active])
        assertNull(f.trust.pins[inactive])
        assertEquals("current-approval", f.trust.pending)
    }

    @Test fun activeTargetDeleteRequiresDisconnectAndSelectsTheNextProfile() {
        val f = Fixture()
        val active = f.activeId()
        val retained = f.store.createSaved("Retained")
        f.trust.pending = "active-review"
        f.prefs.seed("HOME_CONNECTOR", true)
        assertThrows(IllegalStateException::class.java) { f.store.delete(active) }
        assertEquals(active, f.store.state().activeId)
        f.prefs.seed("HOME_CONNECTOR", false)
        f.store.delete(active)
        assertEquals(retained, f.store.state().activeId)
        assertNull(f.trust.pending)
    }

    @Test fun failedInactiveTrustDeletionLeavesItsRegistryAndCurrentSessionUntouched() {
        val f = Fixture()
        f.store.state()
        val inactive = f.store.createSaved("Inactive")
        f.trust.pins[inactive] = "cert"
        val before = f.prefs.values.toMap()
        f.trust.deleteSucceeds = false
        assertThrows(IllegalStateException::class.java) { f.store.delete(inactive) }
        assertEquals(before, f.prefs.values)
        assertEquals("cert", f.trust.pins[inactive])
    }

    @Test fun failedInactiveRegistryDeletionRetainsTheProfileButCannotGiveItAnotherProfilesTrust() {
        val f = Fixture()
        val active = f.activeId()
        val inactive = f.store.createSaved("Inactive")
        f.trust.pins[active] = "active-cert"; f.trust.pins[inactive] = "delete-cert"
        val before = f.prefs.values.toMap()
        f.prefs.failCommits = true
        assertThrows(IllegalStateException::class.java) { f.store.delete(inactive) }
        assertEquals(before, f.prefs.values)
        assertNull(f.trust.pins[inactive])
        assertEquals("active-cert", f.trust.pins[active])
        f.prefs.failCommits = false
        f.store.delete(inactive)
        assertEquals(listOf(active), f.store.state().profiles.map { it.id })
    }

    @Test fun targetedOperationsRejectDeletedOrUnknownIdsInsteadOfFallingBackToCurrent() {
        val f = Fixture()
        f.store.state()
        val inactive = f.store.createSaved("To remove")
        val snapshot = f.store.readForEdit(inactive)
        f.store.delete(inactive)
        val before = f.prefs.values.toMap()
        for (action in listOf<() -> Unit>({ f.store.readForEdit(inactive) }, { f.store.rename(inactive, "No") },
            { f.store.copy(inactive, "No") }, { f.store.delete(inactive) },
            { f.store.saveProfile(snapshot, "No", snapshot.values) })) {
            assertThrows(IllegalStateException::class.java, action)
            assertEquals(before, f.prefs.values)
        }
    }

    @Test fun createSavedHonorsRegistryBoundsWithoutChangingTheActiveIdentity() {
        val f = Fixture()
        val active = f.activeId()
        repeat(99) { f.store.createSaved("Profile $it") }
        val before = f.prefs.values.toMap()
        assertThrows(IllegalArgumentException::class.java) { f.store.createSaved("Too many") }
        assertEquals(before, f.prefs.values)
        assertEquals(active, f.store.state().activeId)
        assertEquals(100, f.store.state().profiles.size)
    }

    @Test fun importedProfileWhileConnectedKeepsTheActiveDraftIdentityGlobalsAndPendingApproval() {
        val f = Fixture()
        val active = f.activeId()
        f.prefs.seed("HOME_PASSWORD", "unsaved-active-draft")
        f.prefs.seed("HOME_CONNECTOR", true)
        f.prefs.seed("HOME_STATUS", "connected")
        f.prefs.seed("CONNECTION_ACCEPTED_SEQUENCE", 12L)
        f.trust.pending = "current-profile-review"
        f.trust.pins[active] = "ab".repeat(32)
        val before = f.prefs.values.toMap()
        val suites = mutableSetOf("import-suite")
        val imported = f.store.importSaved(imported(values = mapOf("HOME_HOSTNAME" to "import.example",
            "SSL_PORT" to "443", "HOME_USERNAME" to "import-user", "HOME_PASSWORD" to "import-secret",
            "BACKEND_MODE" to "ROOT_NATIVE", "SSL_SUITES" to suites)), true)
        assertNotEquals(active, imported)
        assertEquals(active, f.store.state().activeId)
        assertSessionUnchanged(f, before)
        assertTrue(f.store.state().hasUnsavedChanges)
        assertEquals("current-profile-review", f.trust.pending)
        assertEquals("ab".repeat(32), f.trust.pins[active])
        assertEquals("cd".repeat(32), f.trust.pins[imported])
        assertEquals("import-secret", f.store.readForEdit(imported).values["HOME_PASSWORD"])
        suites.add("later-ui-mutation")
        assertEquals(setOf("import-suite"), f.store.readForEdit(imported).values["SSL_SUITES"])
    }

    @Test fun untrustedImportIgnoresTheSuppliedCertificateAndSameNamesStillHaveIndependentIds() {
        val f = Fixture()
        val active = f.activeId()
        val name = f.store.state().profiles.single().name
        val first = f.store.importSaved(imported(name = name, pin = "not-a-pin", der = byteArrayOf(1, 2)), false)
        val second = f.store.importSaved(imported(name = name), false)
        assertEquals(0, f.trust.installCalls)
        assertNotEquals(first, second)
        assertEquals(active, f.store.state().activeId)
        assertEquals(3, f.store.state().profiles.count { it.name == name })
        assertNull(f.trust.pins[first]); assertNull(f.trust.pins[second])
    }

    @Test fun failedImportedTrustCannotPublishAProfileOrChangeTheRunningState() {
        val f = Fixture()
        f.store.ensureInitialized()
        f.prefs.seed("HOME_CONNECTOR", true)
        f.trust.pending = "pending"
        val before = f.prefs.values.toMap()
        f.trust.installSucceeds = false
        assertThrows(IllegalStateException::class.java) { f.store.importSaved(imported(), true) }
        assertEquals(before, f.prefs.values)
        assertEquals("pending", f.trust.pending)
        assertEquals(1, f.store.state().profiles.size)
    }

    @Test fun failedImportedRegistryWriteRestoresTheDraftAndRemovesOnlyItsUnusedTrustScope() {
        val f = Fixture()
        val active = f.activeId()
        f.prefs.seed("HOME_PASSWORD", "active-draft")
        f.trust.pins[active] = "ab".repeat(32)
        f.trust.pending = "pending"
        val before = f.prefs.values.toMap()
        f.prefs.failCommits = true
        assertThrows(IllegalStateException::class.java) { f.store.importSaved(imported(), true) }
        assertEquals(before, f.prefs.values)
        assertEquals(mapOf(active to "ab".repeat(32)), f.trust.pins)
        assertEquals("pending", f.trust.pending)
        f.prefs.failCommits = false
        val added = f.store.importSaved(imported(), true)
        assertNotEquals("profile-2", added)
        assertEquals(active, f.store.state().activeId)
        assertEquals("active-draft", f.prefs.getString("HOME_PASSWORD", null))
    }

    @Test fun importsValidateBoundsAndKeysBeforeInstallingAnyTrust() {
        val f = Fixture()
        f.store.ensureInitialized()
        val before = f.prefs.values.toMap()
        assertThrows(IllegalArgumentException::class.java) {
            f.store.importSaved(imported(values = mapOf("HOME_CONNECTOR" to true)), true)
        }
        assertThrows(IllegalArgumentException::class.java) {
            f.store.importSaved(imported(values = mapOf("HOME_PASSWORD" to "x".repeat(65536))), true)
        }
        assertEquals(before, f.prefs.values)
        assertEquals(0, f.trust.installCalls)
        repeat(99) { f.store.createSaved("Saved $it") }
        val full = f.prefs.values.toMap()
        assertThrows(IllegalArgumentException::class.java) { f.store.importSaved(imported(), true) }
        assertEquals(full, f.prefs.values)
        assertEquals(0, f.trust.installCalls)
    }

    @Test fun generatedTunMacIsSavedWithItsProfileAndDoesNotCreateAnUnsavedDraft() {
        val f = Fixture(legacy = false)
        val id = f.store.importSaved(imported(values = mapOf("BACKEND_MODE" to "TUN")), false)
        val address = f.store.readOrCreateTunMac(id)
        assertTrue(address.matches(Regex("5E[0-9A-F]{10}")))
        assertFalse(f.store.state().hasUnsavedChanges)
        f.prefs.restore()
        val reloaded = ProfileStore(f.prefs, f.trust)
        assertEquals(address, reloaded.readOrCreateTunMac(id))
        assertFalse(reloaded.state().hasUnsavedChanges)
    }

    @Test fun generatingTunMacPreservesButDoesNotSaveAnUnrelatedDraft() {
        val f = Fixture()
        val id = f.activeId()
        val other = f.store.createSaved("Other")
        f.prefs.seed("HOME_HOSTNAME", "unsaved.example")
        val address = f.store.readOrCreateTunMac(id)
        assertTrue(f.store.state().hasUnsavedChanges)
        assertEquals("unsaved.example", f.store.readForEdit(id).values["HOME_HOSTNAME"])
        f.store.select(other, false)
        assertEquals(address, f.store.readForEdit(id).values["ETHERNET_MAC_ADDRESS"])
        assertEquals("first.example", f.store.readForEdit(id).values["HOME_HOSTNAME"])
        assertThrows(IllegalStateException::class.java) { f.store.readOrCreateTunMac(id) }
    }

    @Test fun openingAnExistingRegistryRecoversAnAddressGeneratedByAnOlderApp() {
        val f = Fixture()
        val id = f.activeId()
        val address = "5E0102030405"
        f.prefs.seed("ETHERNET_MAC_ADDRESS", address)
        val reloaded = ProfileStore(f.prefs, f.trust)
        assertFalse(reloaded.state().hasUnsavedChanges)
        val saved = ProfileCodec.decode(f.prefs.getString(ProfileStore.REGISTRY_KEY, null)!!).single()
        assertEquals(id, saved.id)
        assertEquals(address, saved.values["ETHERNET_MAC_ADDRESS"])
    }

    @Test fun importedTunMacIsPreservedEvenWhenAnActiveAddressLooksGenerated() {
        val f = Fixture(legacy = false)
        val address = "02:01:02:03:04:05"
        val id = f.store.importSaved(imported(values = mapOf("BACKEND_MODE" to "TUN",
            "ETHERNET_MAC_ADDRESS" to address)), false)
        assertEquals(address, f.store.readOrCreateTunMac(id))
        assertFalse(f.store.state().hasUnsavedChanges)
        f.prefs.seed("ETHERNET_MAC_ADDRESS", "5E0102030405")
        val reloaded = ProfileStore(f.prefs, f.trust)
        assertTrue(reloaded.state().hasUnsavedChanges)
        val saved = ProfileCodec.decode(f.prefs.getString(ProfileStore.REGISTRY_KEY, null)!!).single()
        assertEquals(address, saved.values["ETHERNET_MAC_ADDRESS"])
    }

    private fun imported(name: String = "Imported", values: Map<String, Any> = mapOf(
        "HOME_HOSTNAME" to "import.example", "SSL_PORT" to "5555", "HOME_HUB" to "DEFAULT",
        "HOME_USERNAME" to "import-user", "HOME_PASSWORD" to "import-secret"),
        pin: String = "cd".repeat(32), der: ByteArray? = null) = ImportedSoftEtherProfile(
        name = name, values = values, certificatePin = pin, certificateDer = der)

    private fun assertSessionUnchanged(f: Fixture, before: Map<String, Any>) {
        assertEquals(before.filterKeys { it != ProfileStore.REGISTRY_KEY },
            f.prefs.values.filterKeys { it != ProfileStore.REGISTRY_KEY })
    }

    private class MemoryPreferences : SharedPreferences {
        val values = linkedMapOf<String, Any>()
        val durable = linkedMapOf<String, Any>()
        var failCommits = false
        fun seed(key: String, value: Any) { values[key] = value; durable[key] = value }
        fun restore() { values.clear(); values.putAll(durable) }
        override fun getAll(): MutableMap<String, *> = values.toMutableMap()
        override fun contains(key: String?) = values.containsKey(key)
        override fun getString(key: String?, defValue: String?): String? = values[key] as? String ?: defValue
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
                if (clear) values.clear()
                changes.forEach { (key, value) -> if (value == null) values.remove(key) else values[key] = value }
                if (failCommits) return false
                durable.clear(); durable.putAll(values)
                return true
            }
            override fun apply() { commit() }
        }
    }
}
