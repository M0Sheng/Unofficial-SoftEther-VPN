package kittoku.mvc.tls

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getIntPrefValue
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.profile.HubCertificateApproval
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.profile.ProfileCodec
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Locale
import java.util.UUID

/** Pins belong to a stable profile and endpoint. Approval and profile switching share one lock. */
internal class CertificateTrustStore(
    private val settings: SharedPreferences,
    internal val preferences: SharedPreferences
) {
    constructor(context: Context) : this(PreferenceManager.getDefaultSharedPreferences(context),
        context.getSharedPreferences("server_certificate_trust", Context.MODE_PRIVATE))

    private fun currentProfileId(): String = settings.getString(ProfileStore.ACTIVE_ID_KEY, null)
        ?.also { CertificateProfileScope.prefix(it) }
        ?: throw IllegalStateException(appText(R.string.profile_runtime_uninitialized_active))

    private fun firstProfileId(): String = settings.getString(ProfileStore.FIRST_ID_KEY, null)
        ?.also { CertificateProfileScope.prefix(it) }
        ?: throw IllegalStateException(appText(R.string.profile_runtime_uninitialized_first))

    internal fun savedPin(profileId: String, host: String, port: Int): String = synchronized(ProfileStore.LOCK) {
        preferences.getString(CertificateProfileScope.key(profileId, CertificateEndpoint.of(host, port)), "").orEmpty()
    }

    internal fun savedPin(host: String, port: Int): String = synchronized(ProfileStore.LOCK) {
        savedPin(currentProfileId(), host, port)
    }

    /** The optional DER is useful only while it identifies this endpoint's current trusted leaf. */
    internal fun savedCertificateDer(profileId: String, host: String, port: Int): ByteArray? = synchronized(ProfileStore.LOCK) {
        val key = CertificateProfileScope.key(profileId, CertificateEndpoint.of(host, port))
        val pin = preferences.getString(key, "").orEmpty()
        decodeMatchingDer(preferences.getString(key + DER_SUFFIX, null), pin)
    }

    /** Refuse a stale or changed pin and restore this operation's trust on failed profile save. */
    internal fun rememberHubCertificate(profileId: String, approval: HubCertificateApproval,
                                        saveProfile: () -> Unit = {}): Boolean = synchronized(ProfileStore.LOCK) {
        val pin = approval.identity.sha256
        if (!pin.matches(PIN) || !approval.identity.isValidAt(System.currentTimeMillis())) return@synchronized false
        val key = CertificateProfileScope.key(profileId, approval.endpoint)
        val beforePin = preferences.getString(key, null)
        if (beforePin.orEmpty() != approval.expectedPin) return@synchronized false
        if (!beforePin.isNullOrEmpty()) {
            if (beforePin != pin) return@synchronized false
            saveProfile()
            return@synchronized true
        }
        val derKey = key + DER_SUFFIX
        val beforeDer = preferences.getString(derKey, null)
        var complete = false
        try {
            if (!preferences.edit().putString(key, pin).remove(derKey).commit()) return@synchronized false
            saveProfile()
            complete = true
            true
        } finally {
            if (!complete) {
                // commit(false) can still expose the attempted change in memory.
                val rollback = preferences.edit().putString(key, beforePin).putString(derKey, beforeDer)
                rollback.commit()
            }
        }
    }

    /** New unpublished scopes only; no accepted/pending identity belonging to an existing profile is changed. */
    internal fun installImportedCertificate(profileId: String, endpoint: CertificateEndpoint,
                                            pin: String, der: ByteArray?): Boolean = synchronized(ProfileStore.LOCK) {
        val prefix = CertificateProfileScope.prefix(profileId)
        if (!pin.matches(PIN) || preferences.all.keys.any { it.startsWith(prefix) }) return@synchronized false
        val registry = runCatching {
            settings.getString(ProfileStore.REGISTRY_KEY, null)?.let(ProfileCodec::decode)
        }.getOrNull() ?: return@synchronized false
        if (registry.any { it.id == profileId } || profileId == settings.getString(ProfileStore.FIRST_ID_KEY, null) ||
            profileId == settings.getString(ProfileStore.ACTIVE_ID_KEY, null) || rawPending()?.profileId == profileId) return@synchronized false
        val bytes = der?.clone()
        if (bytes != null && !matchesDer(bytes, pin)) return@synchronized false
        val key = CertificateProfileScope.key(profileId, endpoint)
        val editor = preferences.edit().putString(key, pin)
        if (bytes != null) editor.putString(key + DER_SUFFIX, Base64.getEncoder().encodeToString(bytes))
        if (editor.commit()) return@synchronized true
        // Android commit(false) may already have published memory. Touch only the
        // unpublished import's two fields; current pins/pending must remain intact.
        preferences.edit().remove(key).remove(key + DER_SUFFIX).commit()
        false
    }

    private fun decodeMatchingDer(encoded: String?, pin: String): ByteArray? {
        if (encoded == null || encoded.length > MAX_DER_BYTES * 4 / 3 + 4 || !pin.matches(PIN)) return null
        return runCatching { Base64.getDecoder().decode(encoded) }.getOrNull()?.takeIf { matchesDer(it, pin) }
    }

    private fun matchesDer(bytes: ByteArray, pin: String): Boolean {
        if (bytes.isEmpty() || bytes.size > MAX_DER_BYTES || !pin.matches(PIN)) return false
        return runCatching {
            val input = ByteArrayInputStream(bytes)
            val certificate = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
            input.available() == 0 && certificate.encoded.contentEquals(bytes) &&
                MessageDigest.getInstance("SHA-256").digest(bytes)
                    .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) } == pin
        }.getOrDefault(false)
    }

    private fun currentEndpoint() = CertificateEndpoint.of(
        getStringPrefValue(MvcPreference.HOME_HOSTNAME, settings),
        getIntPrefValue(MvcPreference.SSL_PORT, settings))

    /**
     * Import pre-profile pins into the first profile. The owner marker, copied pins
     * and source removal share one editor. Always re-commit the marker: commit(false)
     * can publish it only in memory, so observing it is not proof of durability.
     */
    internal fun migrateLegacyTrust(firstProfileId: String) = synchronized(ProfileStore.LOCK) {
        require(firstProfileId == firstProfileId()) { appText(R.string.profile_runtime_migrate_cert_first_only) }
        val prefix = CertificateProfileScope.prefix(firstProfileId)
        val owner = preferences.getString(LEGACY_OWNER, null)
        check(owner == null || owner == firstProfileId) { appText(R.string.profile_runtime_legacy_cert_owner_mismatch) }
        val editor = preferences.edit().putString(LEGACY_OWNER, firstProfileId)
        preferences.all.forEach { (key, value) ->
            if (key.matches(OLD_TRUST_KEY)) {
                val target = prefix + key.removePrefix("trusted_")
                if (value is String && value.matches(PIN) && preferences.getString(target, "").orEmpty().isEmpty()) {
                    editor.putString(target, value)
                }
                editor.remove(key)
            }
        }
        // Old reviews have no immutable profile ID and must never be upgraded.
        val rawPending = preferences.getString(PENDING, null)
        if (rawPending != null && runCatching { CertificateApprovalCodec.decode(rawPending) }.getOrNull() == null) editor.remove(PENDING)
        check(editor.commit()) { appText(R.string.profile_runtime_migrate_cert_failed) }
        migrateManualPin(firstProfileId)
    }

    /** Complete any pending legacy migration before reading or changing certificate approvals. */
    internal fun migrateLegacyPin() = synchronized(ProfileStore.LOCK) { migrateLegacyTrust(firstProfileId()) }

    private fun legacyManualPin() = runCatching { settings.getString(LEGACY_PIN, null) }.getOrNull().orEmpty()
        .filterNot { it == ':' || it.isWhitespace() }.lowercase(Locale.ROOT)

    private fun migrateManualPin(firstId: String) {
        val pin = legacyManualPin()
        if (pin.matches(PIN)) {
            if (settings.getString(ProfileStore.ACTIVE_ID_KEY, null) != firstId) return
            val endpoint = runCatching {
                val host = getStringPrefValue(MvcPreference.HOME_HOSTNAME, settings)
                require(host.isNotBlank() && !host.contains("://") && !host.contains('/'))
                currentEndpoint()
            }.getOrNull() ?: return // A valid source survives an unconfigured first endpoint.
            val key = CertificateProfileScope.key(firstId, endpoint)
            val existing = preferences.getString(key, "").orEmpty()
            val editor = preferences.edit().putString(key, existing.ifEmpty { pin })
            if (existing.isEmpty() || existing == pin) editor.remove(PENDING)
            check(editor.commit()) { appText(R.string.profile_runtime_migrate_cert_failed) }
        }
        // Also flush a removal already published in memory by commit(false).
        check(settings.edit().remove(LEGACY_PIN).commit()) { appText(R.string.profile_runtime_clear_legacy_pin_failed) }
    }

    private fun isCurrent(candidate: CertificateApproval, id: String) = runCatching {
        candidate.canAccept(id, currentProfileId(), currentEndpoint(),
            getStringPrefValue(MvcPreference.BACKEND_MODE, settings),
            savedPin(candidate.profileId, candidate.endpoint.host, candidate.endpoint.port), System.currentTimeMillis())
    }.getOrDefault(false)

    internal fun pending(): CertificateApproval? = synchronized(ProfileStore.LOCK) {
        if (runCatching { migrateLegacyPin() }.isFailure) return@synchronized null
        val encoded = preferences.getString(PENDING, null) ?: return@synchronized null
        val candidate = runCatching { CertificateApprovalCodec.decode(encoded) }.getOrNull()
        if (candidate == null || !isCurrent(candidate, candidate.requestId)) {
            preferences.edit().remove(PENDING).commit()
            return@synchronized null
        }
        candidate
    }

    internal fun beginReview(profileId: String, host: String, port: Int, backendMode: String,
                             review: CertificateReviewException): CertificateApproval? = synchronized(ProfileStore.LOCK) {
        CertificateProfileScope.prefix(profileId)
        val candidate = CertificateApproval(UUID.randomUUID().toString(), profileId, CertificateEndpoint.of(host, port),
            backendMode, review.expectedSha256, review.identity, System.currentTimeMillis())
        if (!isCurrent(candidate, candidate.requestId)) return@synchronized null
        check(preferences.edit().putString(PENDING, CertificateApprovalCodec.encode(candidate)).commit()) { appText(R.string.profile_runtime_save_pending_certificate_failed) }
        candidate
    }

    internal fun accept(requestId: String): Boolean = synchronized(ProfileStore.LOCK) {
        val candidate = pending() ?: return@synchronized false
        if (!isCurrent(candidate, requestId)) return@synchronized false
        val key = CertificateProfileScope.key(candidate.profileId, candidate.endpoint)
        val editor = preferences.edit().putString(key, candidate.identity.sha256).remove(PENDING)
        if (preferences.getString(key, "") != candidate.identity.sha256) editor.remove(key + DER_SUFFIX)
        editor.commit()
    }

    internal fun reject(requestId: String) = synchronized(ProfileStore.LOCK) {
        if (pending()?.requestId == requestId) preferences.edit().remove(PENDING).commit() else false
    }

    internal fun clearPending() = synchronized(ProfileStore.LOCK) { preferences.edit().remove(PENDING).commit() }

    internal fun forget(host: String, port: Int): Boolean = synchronized(ProfileStore.LOCK) {
        forget(currentProfileId(), host, port)
    }

    internal fun forget(profileId: String, host: String, port: Int): Boolean = synchronized(ProfileStore.LOCK) {
        val endpoint = CertificateEndpoint.of(host, port)
        // An unresolved legacy pin has no endpoint snapshot while the first profile
        // is inactive. Do not claim to forget trust that its later migration could
        // restore, or delete an unrelated legacy endpoint's pin. Retry in that profile.
        if (profileId == firstProfileId() && currentProfileId() != profileId && legacyManualPin().matches(PIN)) {
            return@synchronized false
        }
        if (runCatching { migrateLegacyPin() }.isFailure) return@synchronized false
        if (profileId == firstProfileId() && runCatching { currentProfileId() == profileId && currentEndpoint() == endpoint }.getOrDefault(false)) {
            if (!settings.edit().remove(LEGACY_PIN).commit()) return@synchronized false
        }
        val key = CertificateProfileScope.key(profileId, endpoint)
        val beforePin = preferences.getString(key, null)
        val beforeDer = preferences.getString(key + DER_SUFFIX, null)
        val beforePending = preferences.getString(PENDING, null)
        val editor = preferences.edit().remove(key).remove(key + DER_SUFFIX)
        val candidate = rawPending()
        val removedPending = candidate?.profileId == profileId && candidate.endpoint == endpoint
        if (removedPending) editor.remove(PENDING)
        if (editor.commit()) return@synchronized true
        // commit(false) may have published removal in memory despite retaining the
        // old disk state. Restore only this operation's fields, so the UI/CAS retry
        // cannot mistake a failed erase for durable success or overwrite other trust.
        val rollback = preferences.edit()
        if (beforePin == null) rollback.remove(key) else rollback.putString(key, beforePin)
        if (beforeDer == null) rollback.remove(key + DER_SUFFIX) else rollback.putString(key + DER_SUFFIX, beforeDer)
        if (removedPending) {
            if (beforePending == null) rollback.remove(PENDING) else rollback.putString(PENDING, beforePending)
        }
        rollback.commit()
        false
    }

    /** Duplicate accepted pins and their matching optional DER; an in-flight review never becomes trusted. */
    internal fun copyProfileTrust(fromId: String, toId: String): Boolean = synchronized(ProfileStore.LOCK) {
        require(fromId != toId) { appText(R.string.profile_runtime_same_certificate_profiles) }
        val fromPrefix = CertificateProfileScope.prefix(fromId)
        val toPrefix = CertificateProfileScope.prefix(toId)
        if (runCatching { migrateLegacyPin() }.isFailure) return@synchronized false
        val editor = preferences.edit()
        preferences.all.forEach { (key, _) -> if (key.startsWith(toPrefix)) editor.remove(key) }
        preferences.all.forEach { (key, value) ->
            if (key.startsWith(fromPrefix) && key.removePrefix(fromPrefix).matches(PIN) && value is String && value.matches(PIN)) {
                editor.putString(toPrefix + key.removePrefix(fromPrefix), value)
                decodeMatchingDer(preferences.getString(key + DER_SUFFIX, null), value)?.let { der ->
                    editor.putString(toPrefix + key.removePrefix(fromPrefix) + DER_SUFFIX,
                        Base64.getEncoder().encodeToString(der))
                }
            }
        }
        if (rawPending()?.profileId == toId) editor.remove(PENDING)
        editor.putString(FLUSH_TOKEN, UUID.randomUUID().toString()).commit()
    }

    internal fun deleteProfileTrust(profileId: String): Boolean = synchronized(ProfileStore.LOCK) {
        val prefix = CertificateProfileScope.prefix(profileId)
        val firstId = settings.getString(ProfileStore.FIRST_ID_KEY, null)
        // A failed first import can own staged trust before its first ID is published.
        if (firstId != null && runCatching { migrateLegacyPin() }.isFailure) return@synchronized false
        if (profileId == firstId && !settings.edit().remove(LEGACY_PIN).commit()) return@synchronized false
        val editor = preferences.edit()
        preferences.all.forEach { (key, _) -> if (key.startsWith(prefix)) editor.remove(key) }
        if (rawPending()?.profileId == profileId) editor.remove(PENDING)
        editor.putString(FLUSH_TOKEN, UUID.randomUUID().toString()).commit()
    }

    private fun rawPending(): CertificateApproval? = runCatching {
        preferences.getString(PENDING, null)?.let(CertificateApprovalCodec::decode)
    }.getOrNull()

    private companion object {
        const val PENDING = "pending_certificate"
        const val LEGACY_PIN = "TLS_CERT_SHA256"
        const val LEGACY_OWNER = "legacy_profile_trust_owner"
        const val FLUSH_TOKEN = "profile_trust_flush_token"
        const val DER_SUFFIX = "_der"
        const val MAX_DER_BYTES = 128 * 1024
        val PIN = Regex("[0-9a-f]{64}")
        val OLD_TRUST_KEY = Regex("trusted_[0-9a-f]{64}")
    }
}
