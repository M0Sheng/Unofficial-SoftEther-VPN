package kittoku.mvc.preference.custom

import android.content.Context
import android.content.SharedPreferences
import android.util.AttributeSet
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import androidx.preference.Preference
import kittoku.mvc.R
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getIntPrefValue
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.tls.CertificateTrustStore
import kittoku.mvc.profile.ProfileStore

internal class TlsTrustPreference(context: Context, attrs: AttributeSet) : Preference(context, attrs) {
    private val store = CertificateTrustStore(context)
    private val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> refresh() }
    private fun endpoint() = Pair(getStringPrefValue(MvcPreference.HOME_HOSTNAME, sharedPreferences!!),
        getIntPrefValue(MvcPreference.SSL_PORT, sharedPreferences!!))

    private fun refresh() {
        val (host, port) = endpoint()
        val pin = runCatching { store.savedPin(host, port) }.getOrDefault("")
        summary = if (pin.isEmpty()) context.getString(R.string.certificate_trust_empty)
        else context.getString(R.string.certificate_trust_saved, host, port)
        isEnabled = pin.isNotEmpty()
    }

    override fun onAttached() {
        super.onAttached()
        title = context.getString(R.string.certificate_trust_title)
        sharedPreferences!!.registerOnSharedPreferenceChangeListener(listener)
        store.preferences.registerOnSharedPreferenceChangeListener(listener)
        refresh()
        onPreferenceClickListener = OnPreferenceClickListener {
            val (host, port) = endpoint()
            val profileId = sharedPreferences!!.getString(ProfileStore.ACTIVE_ID_KEY, null)
                ?: return@OnPreferenceClickListener false
            val pin = store.savedPin(profileId, host, port)
            MaterialAlertDialogBuilder(context).setTitle(R.string.certificate_trust_title)
                .setMessage("$host:$port\n\nSHA-256\n${pin.chunked(2).joinToString(":")}")
                .setNegativeButton(R.string.action_cancel, null)
                .setPositiveButton(R.string.certificate_forget) { _, _ ->
                    if (store.forget(profileId, host, port)) {
                        DiagnosticLog.record("INFO", "CERTIFICATE", context.getString(R.string.profile_runtime_certificate_renew_log, host, port))
                    } else {
                        DiagnosticLog.record("ERROR", "CERTIFICATE", context.getString(R.string.profile_runtime_certificate_clear_failed_log, host, port))
                        android.widget.Toast.makeText(context, R.string.certificate_forget_failed, android.widget.Toast.LENGTH_LONG).show()
                    }
                }.show()
            true
        }
    }

    override fun onDetached() {
        sharedPreferences?.unregisterOnSharedPreferenceChangeListener(listener)
        store.preferences.unregisterOnSharedPreferenceChangeListener(listener)
        super.onDetached()
    }
}
