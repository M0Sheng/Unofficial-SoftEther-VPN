package kittoku.mvc.profile

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.network.IPv6Policy
import kittoku.mvc.tls.CertificateEndpoint
import kittoku.mvc.tls.CertificateTrustStore
import kittoku.mvc.routing.TunDestinationMode
import kittoku.mvc.routing.TunDestinationSettings
import java.security.SecureRandom
import java.util.HexFormat
import java.util.UUID

internal data class ProfileSummary(val id: String, val name: String, val serverLabel: String)
internal data class ProfileUiState(val activeId: String?, val profiles: List<ProfileSummary>, val hasUnsavedChanges: Boolean)

internal interface ProfileTrust {
    fun migrate(firstId: String)
    fun clearPending(): Boolean
    fun copy(fromId: String, toId: String): Boolean
    fun delete(id: String): Boolean
    fun installImportedCertificate(profileId: String, endpoint: CertificateEndpoint, pin: String, der: ByteArray?): Boolean
}

/** The registry and editable active settings share one durable SharedPreferences transaction.
 * Credentials remain private app data; summaries never contain passwords or usernames.
 */
internal class ProfileStore internal constructor(
    internal val preferences: SharedPreferences,
    private val trust: ProfileTrust,
    private val defaultProfileName: () -> String = { "Default profile" },
    private val newId: () -> String = { UUID.randomUUID().toString() },
) {
    constructor(context: Context) : this(PreferenceManager.getDefaultSharedPreferences(context),
        object : ProfileTrust {
            private val store = CertificateTrustStore(context)
            override fun migrate(firstId: String) = store.migrateLegacyTrust(firstId)
            override fun clearPending() = store.clearPending()
            override fun copy(fromId: String, toId: String) = store.copyProfileTrust(fromId, toId)
            override fun delete(id: String) = store.deleteProfileTrust(id)
            override fun installImportedCertificate(profileId: String, endpoint: CertificateEndpoint, pin: String, der: ByteArray?) =
                store.installImportedCertificate(profileId, endpoint, pin, der)
        }, defaultProfileName = { context.getString(R.string.profile_runtime_default_name) })

    private var initialized = false

    internal fun ensureInitialized(): String? = synchronized(LOCK) {
        if (!initialized) {
            val encoded = preferences.getString(REGISTRY_KEY, null)
            if (encoded == null) {
                check(!preferences.contains(ACTIVE_ID_KEY) && !preferences.contains(FIRST_ID_KEY)) {
                    appText(R.string.profile_runtime_registry_incomplete)
                }
                val working = readWorking()
                if (working.isEmpty()) {
                    persist(emptyList(), null, emptyMap())
                } else {
                    val id = freshId(emptyList())
                    val first = StoredProfile(id, defaultProfileName(), working)
                    persist(listOf(first), id, first.values, firstId = id)
                }
                migrateIpv6Default(null)
            } else {
                val profiles = readProfiles()
                val active = preferences.getString(ACTIVE_ID_KEY, null)
                val valid = if (profiles.isEmpty()) active == null else profiles.any { it.id == active } &&
                    !preferences.getString(FIRST_ID_KEY, null).isNullOrBlank()
                check(valid) { appText(R.string.profile_runtime_active_record_invalid) }
                migrateIpv6Default(profiles.singleOrNull { it.id == active })
                if (active != null) preserveLegacyTunMac(profiles, active)
            }
            // No old trust is removed until the first profile ID is durable.
            preferences.getString(FIRST_ID_KEY, null)?.let(trust::migrate)
            initialized = true
        }
        preferences.getString(ACTIVE_ID_KEY, null)
    }

    private fun migrateIpv6Default(active: StoredProfile?) {
        if (preferences.contains(IPV6_DEFAULT_OFF_KEY)) return
        val key = IPv6Policy.PREFERENCE_KEY
        // The old Settings screen could write the old default only to the active
        // preferences. A saved explicit value still takes precedence on upgrade.
        val oldImplicitDefault = active != null && key !in active.values && preferences.getBoolean(key, false)
        val editor = preferences.edit().putBoolean(IPV6_DEFAULT_OFF_KEY, true)
        if (oldImplicitDefault) editor.remove(key)
        if (!editor.commit()) {
            val rollback = preferences.edit().remove(IPV6_DEFAULT_OFF_KEY)
            if (oldImplicitDefault) rollback.putBoolean(key, true)
            rollback.commit()
            error(appText(R.string.profile_runtime_ipv6_default_failed))
        }
    }

    private fun requireActive(): String = checkNotNull(ensureInitialized()) {
        appText(R.string.profile_runtime_no_profile_selected)
    }

    internal fun state(): ProfileUiState = synchronized(LOCK) {
        val id = ensureInitialized()
        val profiles = readProfiles()
        val working = if (id == null) emptyMap() else readWorking()
        ProfileUiState(id, profiles.map { profile ->
            val values = if (profile.id == id) working else profile.values
            val host = (values["HOME_HOSTNAME"] as? String).orEmpty()
            val display = if (host.contains(':') && !host.startsWith('[')) "[$host]" else host
            val port = (values["SSL_PORT"] as? String)?.toIntOrNull() ?: 5555
            val serverLabel = if (host.isBlank()) appText(R.string.profile_server_empty) else "$display:$port"
            ProfileSummary(profile.id, profile.name, serverLabel)
        }, id != null && withoutImplicitDefaults(working) !=
            withoutImplicitDefaults(profiles.single { it.id == id }.values))
    }

    private fun withoutImplicitDefaults(values: Map<String, Any>): Map<String, Any> =
        values.filterNot { (key, value) ->
            value == IMPLICIT_SETTINGS_DEFAULTS[key] ||
                key == "BACKEND_MODE" && value == BackendModePolicy.RETIRED_ROOT_TAP
        }

    internal fun saveCurrent() = synchronized(LOCK) {
        val id = requireActive()
        val values = readWorking()
        persist(readProfiles().map { if (it.id == id) it.copy(values = values) else it }, id, values)
    }

    /** An editor's target never changes merely because another screen selects a profile. */
    internal fun readForEdit(id: String): StoredProfile = synchronized(LOCK) {
        val active = ensureInitialized()
        val profile = readProfiles().singleOrNull { it.id == id }
            ?: error(appText(R.string.profile_runtime_profile_missing))
        profile.copy(values = copyProfileValues(if (id == active) readWorking() else profile.values))
    }

    internal fun readOrCreateTunMac(id: String): String = synchronized(LOCK) {
        check(ensureInitialized() == id) { appText(R.string.profile_runtime_profile_switched) }
        val working = readWorking()
        working.tunMac()?.let { return@synchronized it }
        val profiles = readProfiles()
        val saved = profiles.single { it.id == id }
        val mac = saved.values.tunMac() ?: HexFormat.of().withUpperCase().formatHex(
            ByteArray(6).also(SecureRandom()::nextBytes).also { it[0] = 0x5e },
        )
        val updated = profiles.map { if (it.id == id) it.copy(values = it.values + (TUN_MAC_KEY to mac)) else it }
        persist(updated, id, working + (TUN_MAC_KEY to mac))
        mac
    }

    private fun preserveLegacyTunMac(profiles: List<StoredProfile>, id: String) {
        // Older clients wrote this generated address only to active preferences.
        // The MAC row is read-only and a user-supplied import is already in the registry.
        val mac = preferences.getString(TUN_MAC_KEY, null) ?: return
        if (!GENERATED_TUN_MAC.matches(mac) || profiles.single { it.id == id }.values.tunMac() != null) return
        val updated = profiles.map { if (it.id == id) it.copy(values = it.values + (TUN_MAC_KEY to mac)) else it }
        persist(updated, id, readWorking())
    }

    private fun Map<String, Any>.tunMac(): String? =
        (this[TUN_MAC_KEY] as? String)?.takeIf { address -> address.any { it != ':' && it != '-' } }

    /** Compare the complete original snapshot so a stale editor cannot overwrite a newer edit. */
    internal fun saveProfile(expected: StoredProfile, name: String, values: Map<String, Any>) = synchronized(LOCK) {
        val active = ensureInitialized()
        val profiles = readProfiles()
        val original = profiles.singleOrNull { it.id == expected.id }
            ?: error(appText(R.string.profile_runtime_profile_missing))
        val working = readWorking()
        val currentValues = if (original.id == active) working else original.values
        check(original.name == expected.name && currentValues == expected.values) {
            appText(R.string.profile_runtime_edited_elsewhere)
        }
        if (original.id == active) requireDisconnected()
        val validName = validateName(name)
        val savedValues = copyProfileValues(values)
        val updated = profiles.map { if (it.id == original.id) it.copy(name = validName, values = savedValues) else it }
        persist(updated, active, if (original.id == active) savedValues else working)
    }

    internal fun rename(id: String, name: String) = synchronized(LOCK) {
        val active = ensureInitialized()
        val profiles = readProfiles()
        check(profiles.any { it.id == id }) { appText(R.string.profile_runtime_profile_missing) }
        val validName = validateName(name)
        persist(profiles.map { if (it.id == id) it.copy(name = validName) else it }, active, readWorking())
    }

    /** Add an empty saved profile and select it if it is the first one. */
    internal fun createSaved(name: String): String = synchronized(LOCK) {
        val active = ensureInitialized()
        val profiles = readProfiles()
        val profile = StoredProfile(freshId(profiles), validateName(name), NEW_PROFILE_VALUES)
        appendSaved(profiles, profile, active)
        profile.id
    }

    /** Preserve an active draft/session when importing into a nonempty registry. */
    internal fun importSaved(profile: ImportedSoftEtherProfile, trustCertificate: Boolean): String = synchronized(LOCK) {
        val active = ensureInitialized()
        val profiles = readProfiles()
        val values = copyProfileValues(profile.values)
        val hasLegacyRoutes = values["ROUTE_MODE"] == "LAN" || !(values["LAN_ROUTES"] as? String).isNullOrBlank()
        val imported = StoredProfile(freshId(profiles), validateName(profile.name),
            if (TunDestinationSettings.MODE_KEY in values || hasLegacyRoutes) values
            else values + (TunDestinationSettings.MODE_KEY to TunDestinationMode.ALL.name))
        // Validate bounds/types before installing trust, including password-safe field limits.
        ProfileCodec.encode(profiles + imported)
        val endpoint = if (trustCertificate) {
            require(profile.certificatePin.matches(Regex("[0-9a-f]{64}"))) {
                appText(R.string.profile_runtime_invalid_import_fingerprint)
            }
            val host = (imported.values["HOME_HOSTNAME"] as? String).orEmpty()
            require(host.isNotBlank() && !host.contains("://") && !host.contains('/') &&
                host.none { it.isWhitespace() || it.isISOControl() }) {
                    appText(R.string.profile_runtime_invalid_import_host)
                }
            val port = if ("SSL_PORT" !in imported.values) 5555
                else (imported.values["SSL_PORT"] as? String)?.toIntOrNull()
            require(port != null && port in 1..65535) { appText(R.string.profile_runtime_invalid_import_port) }
            CertificateEndpoint.of(host, port)
        } else null
        if (endpoint != null) {
            check(trust.installImportedCertificate(imported.id, endpoint, profile.certificatePin,
                profile.certificateDer?.clone())) { appText(R.string.profile_runtime_save_import_certificate_failed) }
        }
        try {
            appendSaved(profiles, imported, active)
        } catch (error: Exception) {
            if (endpoint != null) runCatching { trust.delete(imported.id) }
            throw error
        }
        imported.id
    }

    /** Duplicate a target's independent trust and values without activating the duplicate. */
    internal fun copy(id: String, name: String): String = synchronized(LOCK) {
        val active = ensureInitialized()
        val profiles = readProfiles()
        val source = profiles.singleOrNull { it.id == id }
            ?: error(appText(R.string.profile_runtime_profile_missing))
        val working = readWorking()
        val profile = StoredProfile(freshId(profiles), validateName(name),
            copyProfileValues(if (id == active) working else source.values))
        check(trust.copy(id, profile.id)) { appText(R.string.profile_runtime_copy_certificate_failed) }
        try {
            persist(profiles + profile, active, working)
        } catch (error: Exception) {
            trust.delete(profile.id) // Unpublished random IDs are never selected or reused.
            throw error
        }
        profile.id
    }

    internal fun delete(id: String) = synchronized(LOCK) {
        val active = ensureInitialized()
        if (id == active) return@synchronized deleteCurrent()
        val profiles = readProfiles()
        check(profiles.any { it.id == id }) { appText(R.string.profile_runtime_profile_missing) }
        check(trust.delete(id)) { appText(R.string.profile_runtime_delete_certificate_failed) }
        persist(profiles.filterNot { it.id == id }, active, readWorking())
    }

    internal fun renameCurrent(name: String) = synchronized(LOCK) {
        val id = requireActive()
        val validName = validateName(name)
        val profiles = readProfiles().map { if (it.id == id) it.copy(name = validName) else it }
        // Renaming does not silently save or discard a connection draft.
        persist(profiles, id, readWorking())
    }

    internal fun select(id: String, saveCurrent: Boolean) = synchronized(LOCK) {
        val active = ensureInitialized()
        if (active == id) return@synchronized
        requireDisconnected()
        var profiles = readProfiles()
        val target = profiles.singleOrNull { it.id == id }
            ?: error(appText(R.string.profile_runtime_profile_missing))
        if (saveCurrent) profiles = snapshot(profiles, active)
        check(trust.clearPending()) { appText(R.string.profile_runtime_clear_pending_certificate_failed) }
        persist(profiles, id, target.values, resetStatus = true)
    }

    internal fun create(name: String, saveCurrent: Boolean) = synchronized(LOCK) {
        val active = ensureInitialized()
        requireDisconnected()
        var profiles = readProfiles()
        val profile = StoredProfile(freshId(profiles), validateName(name), NEW_PROFILE_VALUES)
        if (saveCurrent) profiles = snapshot(profiles, active)
        check(trust.clearPending()) { appText(R.string.profile_runtime_clear_pending_certificate_failed) }
        persist(profiles + profile, profile.id, profile.values, firstId = firstIdFor(profile.id), resetStatus = true)
    }

    internal fun copyCurrent(name: String) = synchronized(LOCK) {
        val active = requireActive()
        requireDisconnected()
        val profiles = readProfiles()
        val profile = StoredProfile(freshId(profiles), validateName(name), readWorking())
        check(trust.clearPending()) { appText(R.string.profile_runtime_clear_pending_certificate_failed) }
        // Complete trust before publishing/selecting the new profile. A failed registry
        // write cannot leave a selected profile missing its copied identity.
        check(trust.copy(active, profile.id)) { appText(R.string.profile_runtime_copy_certificate_failed) }
        try {
            persist(profiles + profile, profile.id, profile.values, resetStatus = true)
        } catch (error: Exception) {
            trust.delete(profile.id) // an unused random ID is never reused, even if cleanup fails
            throw error
        }
    }

    internal fun deleteCurrent() = synchronized(LOCK) {
        val active = requireActive()
        requireDisconnected()
        val retained = readProfiles().filterNot { it.id == active }
        val next = retained.firstOrNull()
        check(trust.clearPending()) { appText(R.string.profile_runtime_clear_pending_certificate_failed) }
        // Delete trust first: if the registry write fails, the retained profile will
        // request certificate confirmation again, never gain somebody else's trust.
        check(trust.delete(active)) { appText(R.string.profile_runtime_delete_certificate_failed) }
        persist(retained, next?.id, next?.values.orEmpty(), resetStatus = true)
    }

    private fun appendSaved(profiles: List<StoredProfile>, added: StoredProfile, active: String?) {
        if (active == null) {
            requireDisconnected()
            check(trust.clearPending()) { appText(R.string.profile_runtime_clear_pending_certificate_failed) }
            persist(profiles + added, added.id, added.values, firstId = firstIdFor(added.id), resetStatus = true)
        } else {
            persist(profiles + added, active, readWorking())
        }
    }

    private fun firstIdFor(id: String): String? = id.takeUnless { preferences.contains(FIRST_ID_KEY) }

    private fun requireDisconnected() {
        check(!preferences.getBoolean("HOME_CONNECTOR", false)) {
            appText(R.string.profile_runtime_disconnect_before_switch)
        }
    }

    private fun readProfiles(): List<StoredProfile> = try {
        ProfileCodec.decode(requireNotNull(preferences.getString(REGISTRY_KEY, null)))
    } catch (error: Exception) {
        throw IllegalStateException(appText(R.string.profile_runtime_read_profiles_failed), error)
    }

    private fun readWorking(): Map<String, Any> = preferences.all.filterKeys { it in PROFILE_KEYS }
        .mapValues { (key, value) ->
            require(value != null && ProfileCodec.validValue(key, value)) {
                appText(R.string.profile_runtime_invalid_field_value_for_key, key)
            }
            if (value is Set<*>) value.toSet() else value
        }

    private fun copyProfileValues(values: Map<String, Any>): Map<String, Any> = values.mapValues { (key, value) ->
        require(ProfileCodec.validValue(key, value)) { appText(R.string.profile_runtime_invalid_field_value) }
        if (value is Set<*>) value.toSet() else value
    }

    private fun snapshot(profiles: List<StoredProfile>, active: String?) =
        profiles.map { if (it.id == active) it.copy(values = readWorking()) else it }

    private fun freshId(profiles: List<StoredProfile>): String {
        val id = newId()
        require(id.matches(Regex("[A-Za-z0-9_-]{1,80}")) && profiles.none { it.id == id } &&
            id != preferences.getString(FIRST_ID_KEY, null)) { appText(R.string.profile_runtime_create_profile_id_failed) }
        return id
    }

    private fun persist(profiles: List<StoredProfile>, active: String?, values: Map<String, Any>,
                        firstId: String? = null, resetStatus: Boolean = false) {
        val before = preferences.all.filterKeys { it in TRANSACTION_KEYS }
        val editor = preferences.edit()
        PROFILE_KEYS.forEach(editor::remove)
        values.forEach { (key, value) -> put(editor, key, value) }
        editor.putString(REGISTRY_KEY, ProfileCodec.encode(profiles))
        if (firstId != null) editor.putString(FIRST_ID_KEY, firstId)
        if (active == null) {
            editor.remove(ACTIVE_ID_KEY).remove(ACTIVATION_KEY)
        } else {
            editor.putString(ACTIVE_ID_KEY, active)
            if (firstId != null || resetStatus) editor.putString(ACTIVATION_KEY, UUID.randomUUID().toString())
        }
        if (resetStatus) editor.remove("QUICK_CONNECT_REQUEST_ID").remove("VPN_PERMISSION_PROFILE_ID").remove("VPN_PERMISSION_REQUEST_ID")
            .remove(ProfileConnectionRequest.PROFILE_KEY).remove(ProfileConnectionRequest.NONCE_KEY)
            .remove(ConnectionPhase.KEY).putString("HOME_STATUS", "").putLong("HOME_SESSION_STARTED_AT", 0L)
        if (!editor.commit()) {
            // Android publishes memory even on a failed disk write. Restore the complete
            // prior transaction in memory too, so a later retry cannot save mixed profiles.
            val rollback = preferences.edit()
            TRANSACTION_KEYS.forEach(rollback::remove)
            before.forEach { (key, value) -> if (value != null) put(rollback, key, value) }
            rollback.commit()
            error(appText(R.string.profile_runtime_save_profiles_failed))
        }
        if (firstId != null) initialized = false
    }

    private fun put(editor: SharedPreferences.Editor, key: String, value: Any) {
        when (value) {
            is String -> editor.putString(key, value)
            is Boolean -> editor.putBoolean(key, value)
            is Long -> editor.putLong(key, value)
            is Set<*> -> editor.putStringSet(key, value.map { it as String }.toSet())
            else -> error(appText(R.string.profile_runtime_unsupported_profile_value))
        }
    }

    internal companion object {
        internal val LOCK = Any()
        private const val TUN_MAC_KEY = "ETHERNET_MAC_ADDRESS"
        private const val IPV6_DEFAULT_OFF_KEY = "CONNECTION_IPV6_DEFAULT_OFF"
        private val GENERATED_TUN_MAC = Regex("5E[0-9A-F]{10}")
        internal const val ACTIVE_ID_KEY = "CONNECTION_ACTIVE_PROFILE_ID"
        internal const val FIRST_ID_KEY = "CONNECTION_FIRST_PROFILE_ID"
        internal const val ACTIVATION_KEY = "CONNECTION_PROFILE_ACTIVATION"
        internal const val REGISTRY_KEY = "CONNECTION_PROFILES_V1"
        internal val STRING_KEYS = setOf("HOME_HOSTNAME", "SSL_PORT", "HOME_HUB", "HOME_USERNAME", "HOME_PASSWORD",
            "HOME_AUTH_TYPE", "HOME_CLIENT_CERT", "HOME_CLIENT_KEY",
            "AUTH_PASSWORD_ENCODING", "BACKEND_MODE", "ROUTE_MODE", "LAN_ROUTES", "SSL_VERSION",
            "ETHERNET_MTU", "ETHERNET_MAC_ADDRESS", TunDestinationSettings.MODE_KEY,
            TunDestinationSettings.INCLUDE_KEY, TunDestinationSettings.EXCLUDE_KEY)
        internal val BOOLEAN_KEYS = setOf("SSL_DO_SELECT_SUITES", "UDP_ENABLE_ACCELERATION", "VPN_FORWARD_IPV6", "TUN_FORWARD_IPV6", "NATIVE_MANAGEMENT_ONLY")
        internal val SET_KEYS = setOf("SSL_SUITES")
        internal val PROFILE_KEYS = STRING_KEYS + BOOLEAN_KEYS + SET_KEYS
        // Settings may materialize these defaults on first display. They already
        // apply to profiles where the keys are absent.
        private val IMPLICIT_SETTINGS_DEFAULTS = mapOf(
            "BACKEND_MODE" to BackendModePolicy.ROOT_NATIVE,
            "AUTH_PASSWORD_ENCODING" to "UTF-8",
            IPv6Policy.PREFERENCE_KEY to IPv6Policy.DEFAULT_FORWARDING,
            IPv6Policy.TUN_PREFERENCE_KEY to IPv6Policy.DEFAULT_FORWARDING,
            "NATIVE_MANAGEMENT_ONLY" to false,
            "UDP_ENABLE_ACCELERATION" to false,
        )
        private val NEW_PROFILE_VALUES = mapOf("SSL_PORT" to "443", "HOME_HUB" to "",
            TunDestinationSettings.MODE_KEY to TunDestinationMode.ALL.name,
            TunDestinationSettings.INCLUDE_KEY to "", TunDestinationSettings.EXCLUDE_KEY to "")
        private val TRANSACTION_KEYS = PROFILE_KEYS + setOf(REGISTRY_KEY, ACTIVE_ID_KEY, FIRST_ID_KEY, ACTIVATION_KEY,
            "QUICK_CONNECT_REQUEST_ID", "VPN_PERMISSION_PROFILE_ID", "VPN_PERMISSION_REQUEST_ID", "HOME_STATUS", "HOME_SESSION_STARTED_AT", ConnectionPhase.KEY,
            ProfileConnectionRequest.PROFILE_KEY, ProfileConnectionRequest.NONCE_KEY)

        private fun validateName(name: String): String = name.trim().also {
            require(it.isNotBlank() && it.length <= 64 && it.none(Char::isISOControl)) {
                appText(R.string.profile_runtime_invalid_profile_name)
            }
        }
    }
}
