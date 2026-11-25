package kittoku.mvc.activity

import android.app.Dialog
import android.content.DialogInterface
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import androidx.fragment.app.DialogFragment
import androidx.preference.PreferenceManager
import kittoku.mvc.R
import kittoku.mvc.control.DiagnosticLog
import kittoku.mvc.privacy.PrivacyDisclosure
import kittoku.mvc.profile.ConnectionPhase
import kittoku.mvc.profile.putConnectionStatus
import kittoku.mvc.service.ACTION_VPN_CONNECT
import kittoku.mvc.service.SoftEtherVpnService
import kittoku.mvc.tls.CertificateTrustStore
import java.text.DateFormat
import java.util.Date

class CertificateDialogFragment : DialogFragment() {
    private val requestId get() = requireArguments().getString("requestId").orEmpty()

    override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
        val context = requireContext()
        val store = CertificateTrustStore(context)
        val candidate = store.pending()?.takeIf { it.requestId == requestId }
            ?: return MaterialAlertDialogBuilder(context).setMessage(R.string.certificate_request_expired)
                .setPositiveButton(android.R.string.ok, null).create()
        val identity = candidate.identity
        val changed = candidate.expectedSha256.isNotEmpty()
        val date = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, resources.configuration.locales[0])
        val message = buildString {
            append(getString(if (changed) R.string.certificate_changed_message else R.string.certificate_first_message))
            append("\n\n").append(getString(R.string.certificate_details,
                candidate.endpoint.host, candidate.endpoint.port, identity.subject, identity.issuer,
                date.format(Date(identity.notBeforeMillis)), date.format(Date(identity.notAfterMillis)),
                identity.alternativeNames.ifEmpty { getString(R.string.certificate_no_names) },
                identity.sha256.chunked(2).joinToString(":")))
            if (changed) append("\n\n").append(getString(R.string.certificate_previous,
                candidate.expectedSha256.chunked(2).joinToString(":")))
        }
        return MaterialAlertDialogBuilder(context)
            .setTitle(if (changed) R.string.certificate_changed_title else R.string.certificate_first_title)
            .setMessage(message)
            .setNegativeButton(R.string.action_cancel) { _, _ -> reject() }
            .setPositiveButton(if (changed) R.string.certificate_replace else R.string.certificate_accept) { _, _ ->
                val prefs = PreferenceManager.getDefaultSharedPreferences(context)
                var launch: kittoku.mvc.profile.ProfileConnectionRequest? = null
                try {
                    val disclosuresNeeded = PrivacyDisclosure.pendingConnection(context, prefs) != null
                    val accepted = synchronized(kittoku.mvc.profile.ProfileStore.LOCK) {
                        if (!store.accept(requestId)) false else {
                            if (!disclosuresNeeded && (candidate.backendMode != "TUN" || VpnService.prepare(context) == null)) {
                                launch = kittoku.mvc.profile.ProfileConnectionRequest.reserve(prefs, candidate.profileId)
                            }
                            true
                        }
                    }
                    if (accepted) {
                        DiagnosticLog.record("INFO", "CERTIFICATE", getString(R.string.profile_runtime_certificate_accepted_log, candidate.endpoint.host, candidate.endpoint.port, candidate.identity.sha256))
                        val request = launch
                        if (request == null) {
                            val message = if (disclosuresNeeded) R.string.privacy_connection_required
                                else R.string.certificate_saved_need_permission
                            Toast.makeText(context, message, Toast.LENGTH_LONG).show()
                        } else {
                            context.startForegroundService(Intent(context, SoftEtherVpnService::class.java)
                                .setAction(ACTION_VPN_CONNECT)
                                .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_PROFILE, request.profileId)
                                .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_NONCE, request.nonce)
                                .putExtra(kittoku.mvc.profile.ProfileConnectionRequest.EXTRA_SEQUENCE, request.sequence))
                        }
                    } else {
                        DiagnosticLog.record("WARN", "CERTIFICATE", getString(R.string.profile_runtime_certificate_expired_log))
                        Toast.makeText(context, R.string.certificate_request_expired, Toast.LENGTH_LONG).show()
                    }
                } catch (error: Exception) {
                    launch?.let { kittoku.mvc.profile.ProfileConnectionRequest.cancel(prefs, it) }
                    DiagnosticLog.record("ERROR", "CERTIFICATE", getString(R.string.profile_runtime_certificate_connection_failed_log, error.javaClass.simpleName))
                    Toast.makeText(context, R.string.ui_start_failed_hint, Toast.LENGTH_LONG).show()
                }
            }.create()
    }

    private fun reject() {
        if (CertificateTrustStore(requireContext()).reject(requestId)) {
            DiagnosticLog.record("INFO", "CERTIFICATE", getString(R.string.profile_runtime_certificate_rejected_log))
            PreferenceManager.getDefaultSharedPreferences(requireContext()).edit()
                .putConnectionStatus(ConnectionPhase.DISCONNECTED, getString(R.string.certificate_rejected)).apply()
        }
    }

    override fun onCancel(dialog: DialogInterface) { reject(); super.onCancel(dialog) }

    internal fun matches(id: String) = requestId == id

    companion object {
        internal const val TAG = "server-certificate-review"
        internal fun newInstance(requestId: String) = CertificateDialogFragment().apply {
            arguments = Bundle().apply { putString("requestId", requestId) }
        }
    }
}
