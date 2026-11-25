package kittoku.mvc.profile

import android.content.SharedPreferences

internal data class AcceptedConnection(val profileId: String, val sequence: Long)
internal sealed class RecoveryAction {
    data object None : RecoveryAction()
    data object Reset : RecoveryAction()
    data class Resume(val accepted: AcceptedConnection) : RecoveryAction()
}

/** Runtime ownership is process-local; only an actually accepted service start is recoverable. */
internal open class ConnectionRecoveryState(private val nanoTime: () -> Long = System::nanoTime) {
    private data class RecoveryDispatch(val prefs: SharedPreferences, val sequence: Long, val startedAt: Long)

    private var owner: Any? = null
    private var ownerSequence: Long? = null
    private var permission: Triple<SharedPreferences, String, String>? = null
    private var queued: Pair<SharedPreferences, ProfileConnectionRequest>? = null
    private var recovering: RecoveryDispatch? = null
    private val listeners = linkedSetOf<() -> Unit>()

    fun addListener(listener: () -> Unit) = synchronized(ProfileStore.LOCK) { listeners.add(listener); Unit }
    fun removeListener(listener: () -> Unit) = synchronized(ProfileStore.LOCK) { listeners.remove(listener); Unit }
    fun serviceCreated(token: Any) = synchronized(ProfileStore.LOCK) { owner = token; ownerSequence = null }
    fun serviceAccepted(token: Any, sequence: Long) = synchronized(ProfileStore.LOCK) {
        if (owner === token) ownerSequence = sequence
    }
    fun serviceDestroyed(token: Any) {
        val callbacks = synchronized(ProfileStore.LOCK) {
            if (owner !== token) return
            if (ownerSequence == null) recovering = null
            owner = null; ownerSequence = null
            listeners.toList()
        }
        callbacks.forEach { runCatching(it) }
    }

    fun permissionStarted(prefs: SharedPreferences, id: String, profile: String) = synchronized(ProfileStore.LOCK) {
        permission = Triple(prefs, id, profile)
    }
    fun isLocalPermission(prefs: SharedPreferences, id: String?, profile: String?): Boolean = synchronized(ProfileStore.LOCK) {
        permission?.let { it.first === prefs && it.second == id && it.third == profile } == true
    }
    fun permissionFinished(prefs: SharedPreferences, id: String?, profile: String?) = synchronized(ProfileStore.LOCK) {
        if (isLocalPermission(prefs, id, profile)) permission = null
    }
    fun queued(prefs: SharedPreferences, request: ProfileConnectionRequest) = synchronized(ProfileStore.LOCK) { queued = prefs to request }
    fun queueFinished(prefs: SharedPreferences, profile: String?, nonce: String?) = synchronized(ProfileStore.LOCK) {
        if (queued?.let { it.first === prefs && it.second.profileId == profile && it.second.nonce == nonce } == true) queued = null
    }
    fun stopReserved(prefs: SharedPreferences) = synchronized(ProfileStore.LOCK) {
        if (permission?.first === prefs) permission = null
        if (queued?.first === prefs) queued = null
        if (recovering?.prefs === prefs) recovering = null
    }

    private fun localRequest(prefs: SharedPreferences): Boolean {
        val profile = prefs.getString(ProfileStore.ACTIVE_ID_KEY, null)
        if (permission?.let { it.first === prefs && it.third == profile &&
                prefs.getString("VPN_PERMISSION_REQUEST_ID", null) == it.second &&
                prefs.getString("VPN_PERMISSION_PROFILE_ID", null) == it.third } == true) return true
        return queued?.let { it.first === prefs && it.second.profileId == profile &&
            prefs.getString(ProfileConnectionRequest.NONCE_KEY, null) == it.second.nonce &&
            prefs.getString(ProfileConnectionRequest.PROFILE_KEY, null) == it.second.profileId &&
            prefs.getLong(ProfileConnectionRequest.SEQUENCE_KEY, -1) == it.second.sequence } == true
    }

    fun visibleActive(prefs: SharedPreferences): Boolean = synchronized(ProfileStore.LOCK) {
        prefs.getBoolean("HOME_CONNECTOR", false) &&
            ((owner != null && ownerSequence == prefs.getLong(ProfileConnectionRequest.SEQUENCE_KEY, -1)) ||
                localRequest(prefs) || isRecoveryPending(prefs, accepted(prefs)?.sequence))
    }

    fun accepted(prefs: SharedPreferences): AcceptedConnection? = synchronized(ProfileStore.LOCK) {
        val profile = prefs.getString(ACCEPTED_PROFILE, null) ?: return@synchronized null
        val sequence = prefs.getLong(ACCEPTED_SEQUENCE, -1)
        val activation = prefs.getString(ACCEPTED_ACTIVATION, null)
        if (!prefs.getBoolean("HOME_CONNECTOR", false) || sequence <= 0L ||
            profile != prefs.getString(ProfileStore.ACTIVE_ID_KEY, null) ||
            sequence != prefs.getLong(ProfileConnectionRequest.SEQUENCE_KEY, -1) || activation.isNullOrEmpty() ||
            activation != prefs.getString(ProfileStore.ACTIVATION_KEY, null) ||
            listOf(ProfileConnectionRequest.PROFILE_KEY, ProfileConnectionRequest.NONCE_KEY,
                "VPN_PERMISSION_PROFILE_ID", "VPN_PERMISSION_REQUEST_ID", "QUICK_CONNECT_REQUEST_ID").any(prefs::contains)) return@synchronized null
        AcceptedConnection(profile, sequence)
    }

    fun plan(prefs: SharedPreferences, consentRequired: () -> Boolean, resetMessage: String): RecoveryAction = synchronized(ProfileStore.LOCK) {
        if (localRequest(prefs) || !prefs.getBoolean("HOME_CONNECTOR", false)) return@synchronized RecoveryAction.None
        val accepted = accepted(prefs)
        // Android can create a bound VpnService before delivering any start command.
        if (accepted != null && (ownerSequence == accepted.sequence ||
                isRecoveryPending(prefs, accepted.sequence))) return@synchronized RecoveryAction.None
        if (accepted != null && !consentRequired()) {
            recovering = RecoveryDispatch(prefs, accepted.sequence, nanoTime())
            return@synchronized RecoveryAction.Resume(accepted)
        }
        reset(prefs, resetMessage)
        RecoveryAction.Reset
    }

    private fun isRecoveryPending(prefs: SharedPreferences, sequence: Long?): Boolean = recovering?.let {
        it.prefs === prefs && it.sequence == sequence && nanoTime() - it.startedAt < RECOVERY_DISPATCH_TIMEOUT_NANOS
    } == true

    fun matchesAcceptedStartRetry(prefs: SharedPreferences, profileId: String?, sequence: Long): Boolean =
        accepted(prefs)?.let { it.profileId == profileId && it.sequence == sequence } == true

    /** STICKY and an explicit foreground recovery race through this single owner claim. */
    fun consumeRecovery(prefs: SharedPreferences, token: Any, sequence: Long): Boolean = synchronized(ProfileStore.LOCK) {
        if (owner !== token || ownerSequence != null || localRequest(prefs)) return@synchronized false
        if (accepted(prefs)?.sequence != sequence) return@synchronized false
        ownerSequence = sequence
        if (recovering?.prefs === prefs) recovering = null
        true
    }

    fun recoveryLaunchFailed(prefs: SharedPreferences, sequence: Long, resetMessage: String) = synchronized(ProfileStore.LOCK) {
        if (recovering?.let { it.prefs === prefs && it.sequence == sequence } == true) recovering = null
        if (ownerSequence == null && !localRequest(prefs) && accepted(prefs)?.sequence == sequence) reset(prefs, resetMessage)
    }

    fun resetAbandoned(prefs: SharedPreferences, token: Any, resetMessage: String, expectedSequence: Long? = null) = synchronized(ProfileStore.LOCK) {
        val accepted = accepted(prefs)
        if (owner === token && ownerSequence == null && !localRequest(prefs) &&
            (accepted == null || accepted.sequence == expectedSequence)) reset(prefs, resetMessage)
    }

    /** Returns false if a newer permission/queued start already owns the visible state. */
    fun sessionEnded(prefs: SharedPreferences, token: Any, sequence: Long): Boolean = synchronized(ProfileStore.LOCK) {
        if (owner !== token) return@synchronized false
        if (ownerSequence == sequence) ownerSequence = null
        val editor = prefs.edit()
        if (prefs.getLong(ACCEPTED_SEQUENCE, -1) == sequence) clearAccepted(editor)
        val current = sequence == prefs.getLong(ProfileConnectionRequest.SEQUENCE_KEY, -1) && !localRequest(prefs)
        if (current) editor.putBoolean("HOME_CONNECTOR", false).putLong("HOME_SESSION_STARTED_AT", 0L)
        editor.apply()
        current
    }

    fun wanted(prefs: SharedPreferences, sequence: Long): Boolean = synchronized(ProfileStore.LOCK) {
        accepted(prefs)?.sequence == sequence
    }

    private fun reset(prefs: SharedPreferences, message: String) {
        val sequence = prefs.getLong(ProfileConnectionRequest.SEQUENCE_KEY, 0L)
        val editor = prefs.edit()
        clearAccepted(editor)
        editor.remove(ProfileConnectionRequest.PROFILE_KEY).remove(ProfileConnectionRequest.NONCE_KEY)
            .remove("VPN_PERMISSION_PROFILE_ID").remove("VPN_PERMISSION_REQUEST_ID").remove("QUICK_CONNECT_REQUEST_ID")
            .putBoolean("HOME_CONNECTOR", false).putLong("HOME_SESSION_STARTED_AT", 0L)
            .putConnectionStatus(ConnectionPhase.DISCONNECTED, message)
        if (sequence in 0 until Long.MAX_VALUE) editor.putLong(ProfileConnectionRequest.SEQUENCE_KEY, sequence + 1)
        editor.apply()
        stopReserved(prefs)
    }

    companion object {
        private const val RECOVERY_DISPATCH_TIMEOUT_NANOS = 10_000_000_000L
        const val ACCEPTED_PROFILE = "CONNECTION_ACCEPTED_PROFILE_ID"
        const val ACCEPTED_SEQUENCE = "CONNECTION_ACCEPTED_SEQUENCE"
        const val ACCEPTED_ACTIVATION = "CONNECTION_ACCEPTED_ACTIVATION"
        fun clearAccepted(editor: SharedPreferences.Editor): SharedPreferences.Editor = editor
            .remove(ACCEPTED_PROFILE).remove(ACCEPTED_SEQUENCE).remove(ACCEPTED_ACTIVATION)
    }
}

internal object ConnectionRecovery : ConnectionRecoveryState() {
    const val ACCEPTED_PROFILE = ConnectionRecoveryState.ACCEPTED_PROFILE
    const val ACCEPTED_SEQUENCE = ConnectionRecoveryState.ACCEPTED_SEQUENCE
    const val ACCEPTED_ACTIVATION = ConnectionRecoveryState.ACCEPTED_ACTIVATION
    fun clearAccepted(editor: SharedPreferences.Editor) = ConnectionRecoveryState.clearAccepted(editor)
}
