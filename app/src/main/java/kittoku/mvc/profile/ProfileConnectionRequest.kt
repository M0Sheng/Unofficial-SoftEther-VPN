package kittoku.mvc.profile

import android.content.SharedPreferences
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.util.UUID

/** A queued foreground-service start must still belong to the user's current request. */
internal data class ProfileConnectionRequest(val profileId: String, val nonce: String, val sequence: Long) {
    internal companion object {
        const val PROFILE_KEY = "CONNECTION_START_PROFILE_ID"
        const val NONCE_KEY = "CONNECTION_START_REQUEST_ID"
        const val EXTRA_PROFILE = "connection_profile_id"
        const val EXTRA_NONCE = "connection_request_id"
        const val SEQUENCE_KEY = "CONNECTION_REQUEST_SEQUENCE"
        const val EXTRA_SEQUENCE = "connection_request_sequence"

        fun reserve(prefs: SharedPreferences, profileId: String): ProfileConnectionRequest = synchronized(ProfileStore.LOCK) {
            check(profileId.isNotEmpty() && prefs.getString(ProfileStore.ACTIVE_ID_KEY, null) == profileId) { appText(R.string.profile_runtime_active_profile_changed) }
            val sequence = nextSequence(prefs)
            val request = ProfileConnectionRequest(profileId, UUID.randomUUID().toString(), sequence)
            ConnectionRecovery.clearAccepted(prefs.edit()).putString(PROFILE_KEY, profileId).putString(NONCE_KEY, request.nonce)
                .putLong(SEQUENCE_KEY, sequence).putBoolean("HOME_CONNECTOR", true).apply()
            ConnectionRecovery.queued(prefs, request)
            request
        }

        fun reserveStop(prefs: SharedPreferences): Long = synchronized(ProfileStore.LOCK) {
            val sequence = nextSequence(prefs)
            ConnectionRecovery.clearAccepted(prefs.edit()).remove(PROFILE_KEY).remove(NONCE_KEY).remove("QUICK_CONNECT_REQUEST_ID")
                .remove("VPN_PERMISSION_PROFILE_ID").remove("VPN_PERMISSION_REQUEST_ID")
                .putLong(SEQUENCE_KEY, sequence).putBoolean("HOME_CONNECTOR", false).apply()
            ConnectionRecovery.stopReserved(prefs)
            sequence
        }

        fun consume(prefs: SharedPreferences, profileId: String?, nonce: String?,
                    sequence: Long = prefs.getLong(SEQUENCE_KEY, -1L)): Boolean = synchronized(ProfileStore.LOCK) {
            if (!matches(prefs, profileId, nonce) || prefs.getLong(SEQUENCE_KEY, -1L) != sequence) return@synchronized false
            prefs.edit().remove(PROFILE_KEY).remove(NONCE_KEY).apply()
            ConnectionRecovery.queueFinished(prefs, profileId, nonce)
            true
        }

        /** Only starts actually consumed by the service become eligible for process recovery. */
        fun consumeAndAccept(prefs: SharedPreferences, profileId: String?, nonce: String?, sequence: Long): Boolean = synchronized(ProfileStore.LOCK) {
            if (!matches(prefs, profileId, nonce) || prefs.getLong(SEQUENCE_KEY, -1) != sequence) return@synchronized false
            val activation = prefs.getString(ProfileStore.ACTIVATION_KEY, null) ?: return@synchronized false
            prefs.edit().remove(PROFILE_KEY).remove(NONCE_KEY).remove("QUICK_CONNECT_REQUEST_ID")
                .remove("VPN_PERMISSION_PROFILE_ID").remove("VPN_PERMISSION_REQUEST_ID")
                .putString(ConnectionRecovery.ACCEPTED_PROFILE, profileId)
                .putLong(ConnectionRecovery.ACCEPTED_SEQUENCE, sequence)
                .putString(ConnectionRecovery.ACCEPTED_ACTIVATION, activation).apply()
            ConnectionRecovery.queueFinished(prefs, profileId, nonce)
            true
        }

        fun cancel(prefs: SharedPreferences, request: ProfileConnectionRequest): Boolean = synchronized(ProfileStore.LOCK) {
            if (!matches(prefs, request.profileId, request.nonce)) return@synchronized false
            prefs.edit().remove(PROFILE_KEY).remove(NONCE_KEY).putBoolean("HOME_CONNECTOR", false).apply()
            ConnectionRecovery.queueFinished(prefs, request.profileId, request.nonce)
            true
        }

        fun stopAffectsSession(sessionSequence: Long, stopSequence: Long) = stopSequence > 0L && sessionSequence <= stopSequence

        private fun nextSequence(prefs: SharedPreferences): Long {
            val previous = prefs.getLong(SEQUENCE_KEY, 0L)
            check(previous in 0L until Long.MAX_VALUE) { appText(R.string.profile_runtime_invalid_request_sequence) }
            return previous + 1L
        }

        private fun matches(prefs: SharedPreferences, profileId: String?, nonce: String?): Boolean =
            !profileId.isNullOrEmpty() && !nonce.isNullOrEmpty() &&
                prefs.getString(ProfileStore.ACTIVE_ID_KEY, null) == profileId &&
                prefs.getString(PROFILE_KEY, null) == profileId && prefs.getString(NONCE_KEY, null) == nonce &&
                prefs.getBoolean("HOME_CONNECTOR", false)
    }
}
