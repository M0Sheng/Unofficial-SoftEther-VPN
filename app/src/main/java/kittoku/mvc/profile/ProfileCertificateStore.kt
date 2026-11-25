package kittoku.mvc.profile

import android.content.Context
import android.content.SharedPreferences
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.tls.CertificateEndpoint
import kittoku.mvc.tls.CertificateIdentity
import kittoku.mvc.tls.CertificateTrustStore

/** Public certificate identity only; all fields are immutable and contain no login credentials. */
internal data class ProfileCertificateSnapshot(
    val profileId: String,
    val endpoint: CertificateEndpoint?,
    val pin: String,
)

/** An explicit decision on the leaf presented for a single Hub lookup endpoint. */
internal data class HubCertificateApproval(
    val endpoint: CertificateEndpoint,
    val expectedPin: String,
    val identity: CertificateIdentity,
)

/**
 * Certificate management for the app's automatic TLS connection path. The native
 * management-only mode's independently managed upstream configuration is separate.
 */
internal class ProfileCertificateStore internal constructor(
    private val profiles: ProfileStore,
    private val trust: CertificateTrustStore,
) {
    constructor(context: Context) : this(ProfileStore(context), CertificateTrustStore(context))

    internal val preferences: SharedPreferences get() = trust.preferences

    /** Reads the target's working draft when active, otherwise its saved endpoint. */
    internal fun read(profileId: String): ProfileCertificateSnapshot = synchronized(ProfileStore.LOCK) {
        val profile = profiles.readForEdit(profileId) // Missing IDs never fall back to current.
        val endpoint = endpoint(profile.values)
        ProfileCertificateSnapshot(profile.id, endpoint,
            endpoint?.let { trust.savedPin(profile.id, it.host, it.port) }.orEmpty())
    }

    /** A previously trusted endpoint still has its own pin while editing another address. */
    internal fun lookupPin(expected: StoredProfile, endpoint: CertificateEndpoint): String? = synchronized(ProfileStore.LOCK) {
        if (!matchesEditor(expected)) return@synchronized null
        trust.savedPin(expected.id, endpoint.host, endpoint.port)
    }

    internal fun rememberHubCertificate(expected: StoredProfile, approval: HubCertificateApproval): Boolean =
        synchronized(ProfileStore.LOCK) {
            if (!matchesEditor(expected) || busy(expected.id) || endpoint(expected.values) != approval.endpoint) {
                return@synchronized false
            }
            trust.rememberHubCertificate(expected.id, approval)
        }

    /** Publish a draft's certificate only as part of saving this exact profile and endpoint. */
    internal fun saveProfileWithHubCertificate(expected: StoredProfile, name: String, values: Map<String, Any>,
                                               approval: HubCertificateApproval) = synchronized(ProfileStore.LOCK) {
        check(matchesEditor(expected) && !busy(expected.id) && endpoint(values) == approval.endpoint) {
            appText(R.string.profile_runtime_check_cert_after_change)
        }
        check(trust.rememberHubCertificate(expected.id, approval) { profiles.saveProfile(expected, name, values) }) {
            appText(R.string.profile_runtime_unable_to_save_server_cert)
        }
    }

    /** Atomic compare-and-clear: a stale dialog cannot clear a changed target's identity. */
    internal fun forget(expected: ProfileCertificateSnapshot): Boolean = synchronized(ProfileStore.LOCK) {
        if (expected.endpoint == null || expected.pin.isEmpty()) return@synchronized false
        val current = runCatching { read(expected.profileId) }.getOrNull() ?: return@synchronized false
        if (current != expected) return@synchronized false
        if (busy(expected.profileId)) return@synchronized false
        trust.forget(expected.profileId, expected.endpoint.host, expected.endpoint.port)
    }

    private fun matchesEditor(expected: StoredProfile) =
        runCatching { profiles.readForEdit(expected.id) == expected }.getOrDefault(false)

    private fun busy(profileId: String) = profiles.preferences.getString(ProfileStore.ACTIVE_ID_KEY, null) == profileId &&
        profiles.preferences.getBoolean("HOME_CONNECTOR", false)

    private fun endpoint(values: Map<String, Any>): CertificateEndpoint? {
        val host = (values["HOME_HOSTNAME"] as? String)?.trim().orEmpty()
        if (host.isBlank() || host.contains("://") || host.contains('/') || host.any { it.isWhitespace() || it.isISOControl() }) return null
        val port = if ("SSL_PORT" !in values) 5555 else (values["SSL_PORT"] as? String)?.toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return runCatching { CertificateEndpoint.of(host, port) }.getOrNull()
    }
}
