package kittoku.mvc.profile

import android.content.SharedPreferences
import org.junit.Assert.*
import org.junit.Test

/** Tests simulate a new process by creating a fresh runtime state over the same durable prefs. */
class ConnectionRecoveryTest {
    private class Fixture(nanoTime: () -> Long = System::nanoTime) {
        val prefs = MemoryPreferences().apply {
            seed(ProfileStore.ACTIVE_ID_KEY, "profile-a")
            seed(ProfileStore.ACTIVATION_KEY, "activation-a")
            seed(ProfileConnectionRequest.SEQUENCE_KEY, 0L)
            seed("HOME_CONNECTOR", false)
            seed("HOME_STATUS", "connected")
        }
        val state = ConnectionRecoveryState(nanoTime)
        val owner = Any()
        fun accepted(): ProfileConnectionRequest {
            val request = ProfileConnectionRequest.reserve(prefs, "profile-a")
            assertTrue(ProfileConnectionRequest.consumeAndAccept(prefs, request.profileId, request.nonce, request.sequence))
            return request
        }
        fun permission(id: String = "permission") {
            prefs.edit().putString("VPN_PERMISSION_PROFILE_ID", "profile-a").putString("VPN_PERMISSION_REQUEST_ID", id)
                .putBoolean("HOME_CONNECTOR", true).apply()
            state.permissionStarted(prefs, id, "profile-a")
        }
    }

    @Test fun healthyLiveServiceSurvivesReopenWithoutPreparingOrRestartingAnything() {
        val f = Fixture()
        val accepted = f.accepted()
        f.state.serviceCreated(f.owner)
        f.state.serviceAccepted(f.owner, accepted.sequence)
        var prepared = 0
        assertEquals(RecoveryAction.None, f.state.plan(f.prefs, { prepared++; false }, "reset"))
        assertTrue(f.state.visibleActive(f.prefs))
        assertEquals(0, prepared)
        assertEquals(accepted.sequence, f.state.accepted(f.prefs)!!.sequence)
    }

    @Test fun deadAcceptedConnectionSchedulesOneRecoveryAndStickyAndLauncherCannotBothConsumeIt() {
        val f = Fixture()
        val request = f.accepted()
        val action = f.state.plan(f.prefs, { false }, "reset") as RecoveryAction.Resume
        assertEquals(request.sequence, action.accepted.sequence)
        assertEquals(RecoveryAction.None, f.state.plan(f.prefs, { error("must stay lazy") }, "reset"))
        f.state.serviceCreated(f.owner)
        assertTrue(f.state.consumeRecovery(f.prefs, f.owner, request.sequence))
        assertFalse(f.state.consumeRecovery(f.prefs, f.owner, request.sequence))
        assertEquals(RecoveryAction.None, f.state.plan(f.prefs, { error("live service") }, "reset"))
        assertTrue(f.state.visibleActive(f.prefs))
    }

    @Test fun serviceCreatedByBindingWithoutAStartDoesNotPreventRecovery() {
        val f = Fixture()
        val request = f.accepted()
        f.state.serviceCreated(f.owner)

        assertFalse(f.state.visibleActive(f.prefs))
        assertEquals(RecoveryAction.Resume(AcceptedConnection(request.profileId, request.sequence)),
            f.state.plan(f.prefs, { false }, "reset"))
        assertTrue(f.state.consumeRecovery(f.prefs, f.owner, request.sequence))
    }

    @Test fun serviceDestroyedBeforeAcceptingRecoveryAllowsTheForegroundToTryAgain() {
        val f = Fixture()
        val request = f.accepted()
        val expected = RecoveryAction.Resume(AcceptedConnection(request.profileId, request.sequence))
        assertEquals(expected, f.state.plan(f.prefs, { false }, "reset"))
        f.state.serviceCreated(f.owner)
        f.state.serviceDestroyed(f.owner)

        assertEquals(expected, f.state.plan(f.prefs, { false }, "reset"))
    }

    @Test fun recoveryDispatchThatNeverReachesTheServiceExpires() {
        var now = 100L
        val f = Fixture { now }
        val request = f.accepted()
        val expected = RecoveryAction.Resume(AcceptedConnection(request.profileId, request.sequence))
        assertEquals(expected, f.state.plan(f.prefs, { false }, "reset"))
        assertTrue(f.state.visibleActive(f.prefs))
        assertEquals(RecoveryAction.None, f.state.plan(f.prefs, { false }, "reset"))

        now += 11_000_000_000L
        assertFalse(f.state.visibleActive(f.prefs))
        assertEquals(expected, f.state.plan(f.prefs, { false }, "reset"))
    }

    @Test fun foregroundLaunchFailureCanClearAnUnclaimedStartOnABoundService() {
        val f = Fixture()
        val request = f.accepted()
        f.state.serviceCreated(f.owner)
        assertTrue(f.state.plan(f.prefs, { false }, "reset") is RecoveryAction.Resume)

        f.state.recoveryLaunchFailed(f.prefs, request.sequence, "start rejected")
        assertFalse(f.prefs.getBoolean("HOME_CONNECTOR", true))
        assertEquals("start rejected", f.prefs.getString("HOME_STATUS", null))
    }

    @Test fun deliveryRetryMustMatchTheCurrentlyAcceptedProfileAndSequence() {
        val f = Fixture()
        val request = f.accepted()
        assertFalse(ProfileConnectionRequest.consumeAndAccept(f.prefs, request.profileId, request.nonce, request.sequence))
        assertTrue(f.state.matchesAcceptedStartRetry(f.prefs, request.profileId, request.sequence))
        assertFalse(f.state.matchesAcceptedStartRetry(f.prefs, "profile-b", request.sequence))
        assertFalse(f.state.matchesAcceptedStartRetry(f.prefs, request.profileId, request.sequence - 1))

        ProfileConnectionRequest.reserveStop(f.prefs)
        assertFalse(f.state.matchesAcceptedStartRetry(f.prefs, request.profileId, request.sequence))
    }

    @Test fun legacy181BusyFlagAndTimestampBecomeOneTapStartRatherThanAnUnprovenRecovery() {
        val f = Fixture()
        f.prefs.seed("HOME_CONNECTOR", true)
        f.prefs.seed("HOME_SESSION_STARTED_AT", 1_000L)
        assertEquals(RecoveryAction.Reset, f.state.plan(f.prefs, { error("not an accepted session") }, "ended"))
        assertFalse(f.prefs.getBoolean("HOME_CONNECTOR", true))
        assertEquals("ended", f.prefs.getString("HOME_STATUS", null))
        assertEquals(0L, f.prefs.getLong("HOME_SESSION_STARTED_AT", -1))
        assertEquals(1L, f.prefs.getLong(ProfileConnectionRequest.SEQUENCE_KEY, -1))
    }

    @Test fun genuineLocalPermissionIsPreservedButTheSamePersistedFlagsInANewProcessAreNot() {
        val f = Fixture()
        f.permission()
        assertEquals(RecoveryAction.None, f.state.plan(f.prefs, { error("local permission") }, "reset"))
        assertTrue(f.state.visibleActive(f.prefs))
        assertTrue(f.state.isLocalPermission(f.prefs, "permission", "profile-a"))
        val newProcess = ConnectionRecoveryState()
        assertEquals(RecoveryAction.Reset, newProcess.plan(f.prefs, { error("no accepted session") }, "ended"))
        assertFalse(f.prefs.contains("VPN_PERMISSION_REQUEST_ID"))
        assertFalse(f.prefs.getBoolean("HOME_CONNECTOR", true))
    }

    @Test fun localQueuedStartIsPreservedButADeadProcessesQueueCannotLaterConnect() {
        val f = Fixture()
        val request = ProfileConnectionRequest.reserve(f.prefs, "profile-a")
        f.state.queued(f.prefs, request)
        assertEquals(RecoveryAction.None, f.state.plan(f.prefs, { error("local queue") }, "reset"))
        val newProcess = ConnectionRecoveryState()
        assertEquals(RecoveryAction.Reset, newProcess.plan(f.prefs, { error("queue is not acceptance") }, "reset"))
        assertFalse(ProfileConnectionRequest.consumeAndAccept(f.prefs, request.profileId, request.nonce, request.sequence))
    }

    @Test fun acceptedRecordWithAnyUnresolvedPermissionOrQueueTokenCannotReviveAnOldSession() {
        for (key in listOf("VPN_PERMISSION_PROFILE_ID", "VPN_PERMISSION_REQUEST_ID", "QUICK_CONNECT_REQUEST_ID",
            ProfileConnectionRequest.PROFILE_KEY, ProfileConnectionRequest.NONCE_KEY)) {
            val f = Fixture()
            f.accepted()
            f.prefs.seed(key, "abandoned")
            assertNull(f.state.accepted(f.prefs))
            assertEquals(RecoveryAction.Reset, f.state.plan(f.prefs, { error("stale token") }, "reset"))
            assertFalse(f.prefs.contains(key))
        }
    }

    @Test fun stopAtomicallyClearsAcceptedIntentAndCancelsAnAlreadyQueuedRecovery() {
        val f = Fixture()
        val request = f.accepted()
        assertTrue(f.state.plan(f.prefs, { false }, "reset") is RecoveryAction.Resume)
        val stop = ProfileConnectionRequest.reserveStop(f.prefs)
        assertTrue(stop > request.sequence)
        assertFalse(f.prefs.getBoolean("HOME_CONNECTOR", true))
        assertFalse(f.prefs.contains(ConnectionRecovery.ACCEPTED_SEQUENCE))
        assertFalse(f.prefs.contains(ConnectionRecovery.ACCEPTED_PROFILE))
        f.state.serviceCreated(f.owner)
        assertFalse(f.state.consumeRecovery(f.prefs, f.owner, request.sequence))
        assertFalse(f.state.visibleActive(f.prefs))
    }

    @Test fun mismatchedProfileActivationOrSequenceFailsClosedWithoutCallingPrepare() {
        for ((key, value) in listOf(ProfileStore.ACTIVE_ID_KEY to "profile-b",
            ProfileStore.ACTIVATION_KEY to "new-activation", ProfileConnectionRequest.SEQUENCE_KEY to 20L)) {
            val f = Fixture()
            f.accepted()
            f.prefs.seed(key, value)
            assertEquals(RecoveryAction.Reset, f.state.plan(f.prefs, { error("wrong identity") }, "reset"))
            assertNull(f.state.accepted(f.prefs))
        }
    }

    @Test fun onlyAValidAcceptedSessionMayAskWhetherTunNeedsFreshConsent() {
        val f = Fixture()
        f.accepted()
        f.prefs.seed("unrelated_public_marker", "preserved")
        var asked = 0
        assertEquals(RecoveryAction.Reset, f.state.plan(f.prefs, { asked++; true }, "needs permission"))
        assertEquals(1, asked)
        assertFalse(f.prefs.getBoolean("HOME_CONNECTOR", true))
        assertEquals("preserved", f.prefs.getString("unrelated_public_marker", null))
    }

    @Test fun oldSessionFinishCannotClobberANewerQueuedStartsVisibleState() {
        val f = Fixture()
        val old = f.accepted()
        f.state.serviceCreated(f.owner); f.state.serviceAccepted(f.owner, old.sequence)
        val newer = ProfileConnectionRequest.reserve(f.prefs, "profile-a")
        f.state.queued(f.prefs, newer)
        assertFalse(f.state.sessionEnded(f.prefs, f.owner, old.sequence))
        assertTrue(f.prefs.getBoolean("HOME_CONNECTOR", false))
        assertEquals(newer.nonce, f.prefs.getString(ProfileConnectionRequest.NONCE_KEY, null))
        assertEquals("connected", f.prefs.getString("HOME_STATUS", null))
    }

    @Test fun oldFinishCannotClobberANewLocalPermissionEvenBeforeItsSequenceAdvances() {
        val f = Fixture()
        val old = f.accepted()
        f.state.serviceCreated(f.owner); f.state.serviceAccepted(f.owner, old.sequence)
        f.permission("new-permission")
        assertFalse(f.state.sessionEnded(f.prefs, f.owner, old.sequence))
        assertTrue(f.prefs.getBoolean("HOME_CONNECTOR", false))
        assertEquals("new-permission", f.prefs.getString("VPN_PERMISSION_REQUEST_ID", null))
        assertTrue(f.state.visibleActive(f.prefs))
    }

    @Test fun onlyTheCurrentServiceOwnerCanReleaseRuntimeOwnership() {
        val f = Fixture()
        val accepted = f.accepted()
        var released = 0
        f.state.addListener { released++ }
        f.state.serviceCreated(f.owner)
        val newerOwner = Any()
        f.state.serviceCreated(newerOwner)
        f.state.serviceAccepted(newerOwner, accepted.sequence)
        f.state.serviceDestroyed(f.owner)
        assertEquals(0, released)
        assertTrue(f.state.visibleActive(f.prefs))
        f.state.serviceDestroyed(newerOwner)
        assertEquals(1, released)
        assertEquals(accepted.sequence, f.state.accepted(f.prefs)!!.sequence)
        assertTrue(f.state.plan(f.prefs, { false }, "reset") is RecoveryAction.Resume)
    }

    @Test fun staleRecoveryIntentCannotResetOrConsumeANewerAcceptedRecord() {
        val f = Fixture()
        val old = f.accepted()
        val newer = f.accepted()
        f.state.serviceCreated(f.owner)
        assertFalse(f.state.consumeRecovery(f.prefs, f.owner, old.sequence))
        f.state.resetAbandoned(f.prefs, f.owner, "wrong reset", expectedSequence = old.sequence)
        assertEquals(newer.sequence, f.state.accepted(f.prefs)!!.sequence)
        assertTrue(f.state.consumeRecovery(f.prefs, f.owner, newer.sequence))
    }

    @Test fun permissionCancellationCanReleaseOnlyItsOwnClaim() {
        val f = Fixture()
        f.permission("old")
        f.permission("new")
        f.state.permissionFinished(f.prefs, "old", "profile-a")
        assertTrue(f.state.isLocalPermission(f.prefs, "new", "profile-a"))
        assertEquals(RecoveryAction.None, f.state.plan(f.prefs, { error("new local permission") }, "reset"))
    }

    @Test fun staleRecoveryLaunchFailureCannotClearANewerRequest() {
        val f = Fixture()
        val old = f.accepted()
        assertTrue(f.state.plan(f.prefs, { false }, "reset") is RecoveryAction.Resume)
        val newer = f.accepted()
        f.state.recoveryLaunchFailed(f.prefs, old.sequence, "failed old launch")
        assertEquals(newer.sequence, f.state.accepted(f.prefs)!!.sequence)
        assertTrue(f.prefs.getBoolean("HOME_CONNECTOR", false))
    }

    @Test fun tileShowsActualRuntimeOrPendingRecoveryRatherThanPersistedConnectedText() {
        val f = Fixture()
        f.accepted()
        assertFalse(f.state.visibleActive(f.prefs))
        assertTrue(f.state.plan(f.prefs, { false }, "reset") is RecoveryAction.Resume)
        assertTrue(f.state.visibleActive(f.prefs))
        ProfileConnectionRequest.reserveStop(f.prefs)
        assertFalse(f.state.visibleActive(f.prefs))
    }

    @Test fun acceptingTheServiceRequestAtomicallyRemovesOldUiTokensAndCapturesItsIdentity() {
        val f = Fixture()
        val request = ProfileConnectionRequest.reserve(f.prefs, "profile-a")
        f.prefs.seed("QUICK_CONNECT_REQUEST_ID", "quick")
        f.prefs.seed("VPN_PERMISSION_REQUEST_ID", "permission")
        f.prefs.seed("VPN_PERMISSION_PROFILE_ID", "profile-a")
        assertFalse(ProfileConnectionRequest.consumeAndAccept(f.prefs, request.profileId, "wrong", request.sequence))
        assertNull(f.state.accepted(f.prefs))
        assertTrue(ProfileConnectionRequest.consumeAndAccept(f.prefs, request.profileId, request.nonce, request.sequence))
        assertEquals(AcceptedConnection("profile-a", request.sequence), f.state.accepted(f.prefs))
        assertFalse(f.prefs.contains("QUICK_CONNECT_REQUEST_ID"))
        assertFalse(f.prefs.contains("VPN_PERMISSION_REQUEST_ID"))
    }

    private class MemoryPreferences : SharedPreferences {
        private val values = linkedMapOf<String, Any>()
        fun seed(key: String, value: Any) { values[key] = value }
        override fun getAll(): MutableMap<String, *> = values.toMutableMap()
        override fun contains(key: String?) = values.containsKey(key)
        override fun getString(key: String?, defValue: String?) = values[key] as? String ?: defValue
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?) = (values[key] as? Set<String>)?.toMutableSet() ?: defValues
        override fun getInt(key: String?, defValue: Int) = values[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long) = values[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float) = values[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean) = values[key] as? Boolean ?: defValue
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
            val changes = linkedMapOf<String, Any?>()
            var clear = false
            private fun put(key: String?, value: Any?): SharedPreferences.Editor { changes[requireNotNull(key)] = value; return this }
            override fun putString(key: String?, value: String?) = put(key, value)
            override fun putStringSet(key: String?, values: MutableSet<String>?) = put(key, values?.toSet())
            override fun putBoolean(key: String?, value: Boolean) = put(key, value)
            override fun putLong(key: String?, value: Long) = put(key, value)
            override fun putInt(key: String?, value: Int) = put(key, value)
            override fun putFloat(key: String?, value: Float) = put(key, value)
            override fun remove(key: String?) = put(key, null)
            override fun clear(): SharedPreferences.Editor { clear = true; return this }
            override fun commit(): Boolean {
                if (clear) values.clear()
                changes.forEach { (key, value) -> if (value == null) values.remove(key) else values[key] = value }
                return true
            }
            override fun apply() { commit() }
        }
    }
}
