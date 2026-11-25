package kittoku.mvc.activity

import androidx.lifecycle.ViewModel
import kittoku.mvc.nativecore.NativeAuthMode
import kittoku.mvc.profile.HubCertificateApproval
import kittoku.mvc.profile.StoredProfile

/** RAM only: no SavedStateHandle, Parcelable, Intent extra or diagnostic representation. */
internal class ProfileEditorViewModel : ViewModel() {
    var expected: StoredProfile? = null
        private set
    var name = ""
    var hubCertificateApproval: HubCertificateApproval? = null
    val fields = linkedMapOf<String, String>()
    private var originalName = ""
    private var originalFields: Map<String, String> = emptyMap()
    val initialized: Boolean get() = expected != null
    val dirty: Boolean get() = name != originalName || fields != originalFields
    var authMode: NativeAuthMode
        get() = NativeAuthMode.entries.firstOrNull { it.name == fields["HOME_AUTH_TYPE"] } ?: NativeAuthMode.STANDARD_PASSWORD
        set(mode) { fields["HOME_AUTH_TYPE"] = mode.name }

    fun initialize(profile: StoredProfile) {
        expected = profile
        name = profile.name
        hubCertificateApproval = null
        originalName = profile.name
        fields.clear()
        FIELDS.forEach { key ->
            fields[key] = profile.values[key] as? String ?: when (key) {
                "SSL_PORT" -> "5555"
                "HOME_AUTH_TYPE" -> NativeAuthMode.STANDARD_PASSWORD.name
                else -> ""
            }
        }
        originalFields = fields.toMap()
    }

    fun mergedValues(): Map<String, Any> {
        // Preserve all fields that this connection form does not expose.
        val saved = requireNotNull(expected).values
        return saved.toMutableMap().apply {
            putAll(fields)
            // Preserve older profiles that use the connection fallback for a missing Hub.
            if ("HOME_HUB" !in saved && fields["HOME_HUB"].isNullOrEmpty()) remove("HOME_HUB")
            if (!authMode.usesPassword) remove("HOME_PASSWORD")
            if (authMode != NativeAuthMode.CLIENT_CERTIFICATE) {
                remove("HOME_CLIENT_CERT")
                remove("HOME_CLIENT_KEY")
            }
            if (authMode == NativeAuthMode.STANDARD_PASSWORD && "HOME_AUTH_TYPE" !in saved) remove("HOME_AUTH_TYPE")
        }
    }

    fun clearSensitive() {
        expected = null
        hubCertificateApproval = null
        fields.clear()
        originalFields = emptyMap()
        name = ""
        originalName = ""
    }

    override fun onCleared() { clearSensitive() }

    companion object {
        val FIELDS = listOf("HOME_HOSTNAME", "SSL_PORT", "HOME_HUB", "HOME_USERNAME", "HOME_PASSWORD",
            "HOME_AUTH_TYPE", "HOME_CLIENT_CERT", "HOME_CLIENT_KEY")
    }
}
