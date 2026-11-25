package kittoku.mvc.fragment

import android.app.LocaleManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.LocaleList
import android.provider.Settings
import androidx.preference.DropDownPreference
import androidx.preference.MultiSelectListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.PreferenceGroup
import androidx.preference.PreferenceScreen
import androidx.recyclerview.widget.RecyclerView
import kittoku.mvc.R
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.custom.DestinationRoutingPreference
import kittoku.mvc.preference.custom.ThemePreference
import kittoku.mvc.activity.AppRoutingActivity
import kittoku.mvc.routing.AppRoutingMode
import kittoku.mvc.routing.AppRoutingSettings
import kittoku.mvc.routing.TunDestinationSettings
import kittoku.mvc.activity.LogActivity
import kittoku.mvc.activity.NativeCommandActivity
import kittoku.mvc.activity.ThemeSettingsActivity
import kittoku.mvc.service.VpnTileService
import android.graphics.drawable.Icon
import android.content.ComponentName
import android.app.StatusBarManager
import android.widget.Toast
import android.Manifest
import android.content.pm.PackageManager
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.view.View
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kittoku.mvc.activity.NativeRemotePasswordDialogFragment
import kittoku.mvc.nativecore.NativeCoreRunner
import kittoku.mvc.nativecore.NativeRemoteManagementSettings
import kittoku.mvc.network.IPv6Policy
import kittoku.mvc.preference.accessor.getStringPrefValue
import java.net.Inet6Address
import java.net.NetworkInterface
import androidx.activity.result.contract.ActivityResultContracts
import androidx.preference.SwitchPreferenceCompat
import kittoku.mvc.preference.ProfilePreferenceGuard
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.ui.AccentSettings
import kittoku.mvc.ui.ThemeSettings
import javax.net.ssl.SSLContext


internal class SettingFragment : PreferenceFragmentCompat() {
    private val profiles by lazy { ProfileStore(requireContext()) }
    private val appRouting by lazy { AppRoutingSettings(requireContext()) }
    private val preferenceGuard by lazy { ProfilePreferenceGuard(this, profiles) }
    private var renderedProfile: Pair<String?, String?>? = null
    private val profileRefresh = Runnable { refreshProfileScreen() }
    private val remoteManagement by lazy { NativeRemoteManagementSettings(requireContext()) }
    private val settingsHandler = Handler(Looper.getMainLooper())
    private val settingsListener = SharedPreferences.OnSharedPreferenceChangeListener { _, changed ->
        if (changed == null || changed == ProfileStore.ACTIVE_ID_KEY || changed == ProfileStore.ACTIVATION_KEY) {
            settingsHandler.removeCallbacks(profileRefresh)
            settingsHandler.post(profileRefresh)
        }
        when (changed) {
            null, MvcPreference.BACKEND_MODE.name, MvcPreference.ROUTE_MODE.name,
            TunDestinationSettings.MODE_KEY, TunDestinationSettings.INCLUDE_KEY, TunDestinationSettings.EXCLUDE_KEY,
            MvcPreference.SSL_DO_SELECT_SUITES.name,
            ThemeSettings.PREFERENCE_KEY,
            AccentSettings.PREFERENCE_KEY, NativeRemoteManagementSettings.ENABLED_KEY,
            NativeRemoteManagementSettings.PASSWORD_CHANGED_AT_KEY ->
                settingsHandler.post { if (isAdded) refreshSettingsOptions() }
            else -> Unit
        }
    }
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) {
            preferenceManager.sharedPreferences?.edit()?.putBoolean("SHOW_NOTIFICATION_TRAFFIC", false)?.apply()
            findPreference<SwitchPreferenceCompat>("SHOW_NOTIFICATION_TRAFFIC")?.isChecked = false
            context?.let { Toast.makeText(it, R.string.notification_traffic_permission_denied, Toast.LENGTH_LONG).show() }
        }
    }
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        profiles.ensureInitialized()
        inflateSettings(rootKey)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        setDivider(null)
        setDividerHeight(0)
        val background = MaterialColors.getColor(view, com.google.android.material.R.attr.colorSurface)
        view.setBackgroundColor(background)
        listView.apply {
            setBackgroundColor(background)
            clipToPadding = false
            val inset = resources.getDimensionPixelSize(R.dimen.ui_page_inset)
            setPaddingRelative(0, 0, 0, inset)
            // Avoid animations while backend/profile changes replace visible rows.
            itemAnimator = null
        }
    }

    private fun inflateSettings(rootKey: String? = null) {
        preferenceGuard.prepareInflation()
        setPreferencesFromResource(R.xml.setting, rootKey)
        removeEmptyIconSpacing(preferenceScreen)

        configureTlsOptions()
        configureRemoteManagement()
        configureAppLanguage()
        findPreference<ThemePreference>(ThemeSettings.PREFERENCE_KEY)?.setOnPreferenceClickListener {
            startActivity(Intent(requireContext(), ThemeSettingsActivity::class.java))
            true
        }
        findPreference<Preference>("APP_BATTERY_USAGE")?.setOnPreferenceClickListener {
            val context = requireContext()
            val appDetails = Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", context.packageName, null),
            )
            try {
                startActivity(appDetails)
            } catch (_: ActivityNotFoundException) {
                Toast.makeText(context, R.string.app_battery_usage_open_failed, Toast.LENGTH_LONG).show()
            }
            true
        }
        findPreference<Preference>("DIAGNOSTIC_LOGS")?.setOnPreferenceClickListener {
            startActivity(Intent(requireContext(), LogActivity::class.java))
            true
        }
        findPreference<Preference>("UI_ABOUT")?.apply {
            summary = getString(R.string.ui_about_summary, kittoku.mvc.BuildConfig.VERSION_NAME)
            setOnPreferenceClickListener {
                (activity as? kittoku.mvc.activity.MainActivity)?.openPage(kittoku.mvc.activity.MainActivity.PAGE_ABOUT)
                true
            }
        }
        findPreference<SwitchPreferenceCompat>("SHOW_NOTIFICATION_TRAFFIC")?.setOnPreferenceChangeListener { _, value ->
            if (value == true && requireContext().checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
            true
        }
        findPreference<Preference>("APP_ROUTING")?.setOnPreferenceClickListener {
            startActivity(Intent(requireContext(), AppRoutingActivity::class.java)); true
        }
        findPreference<Preference>("NATIVE_COMMAND")?.setOnPreferenceClickListener {
            startActivity(Intent(requireContext(), NativeCommandActivity::class.java)); true
        }
        findPreference<Preference>("ADD_QUICK_TILE")?.setOnPreferenceClickListener {
                val manager = requireContext().getSystemService(StatusBarManager::class.java)
                manager.requestAddTileService(ComponentName(requireContext(), VpnTileService::class.java),
                    getString(R.string.app_name_short), Icon.createWithResource(requireContext(), R.drawable.ic_lan_bridge_mono),
                    requireContext().mainExecutor) { result ->
                    val appContext = context?.applicationContext ?: return@requestAddTileService
                    Toast.makeText(appContext, if (result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ADDED ||
                        result == StatusBarManager.TILE_ADD_REQUEST_RESULT_TILE_ALREADY_ADDED) R.string.quick_tile_added
                        else R.string.quick_tile_not_added, Toast.LENGTH_LONG).show()
                }
            true
        }
        renderedProfile = currentProfile()
        refreshSettingsOptions()
    }

    private fun configureAppLanguage() {
        val preference = findPreference<Preference>("APP_LANGUAGE") ?: return
        val manager = requireContext().getSystemService(LocaleManager::class.java) ?: return
        val labels = arrayOf(
            getString(R.string.app_language_system),
            getString(R.string.app_language_english),
            getString(R.string.app_language_simplified_chinese),
            getString(R.string.app_language_japanese),
        )
        val tags = arrayOf("", "en", "zh-CN", "ja")
        val selected = when (manager.applicationLocales[0]?.language) {
            "en" -> 1
            "zh" -> 2
            "ja" -> 3
            else -> 0
        }
        preference.summary = labels[selected]
        preference.setOnPreferenceClickListener {
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.app_language)
                .setSingleChoiceItems(labels, selected) { dialog, index ->
                    dialog.dismiss()
                    if (index != selected) {
                        manager.applicationLocales = LocaleList.forLanguageTags(tags[index])
                    }
                }
                .setNegativeButton(R.string.action_cancel, null)
                .show()
            true
        }
    }

    private fun removeEmptyIconSpacing(preference: Preference) {
        if (preference.icon == null) preference.isIconSpaceReserved = false
        if (preference is PreferenceGroup) {
            for (index in 0 until preference.preferenceCount) {
                removeEmptyIconSpacing(preference.getPreference(index))
            }
        }
    }

    override fun onCreateAdapter(preferenceScreen: PreferenceScreen): RecyclerView.Adapter<*> {
        val adapter = preferenceGuard.unavailableSettingsAdapter(preferenceScreen) ?: super.onCreateAdapter(preferenceScreen)
        preferenceGuard.bindAfterAdapter(preferenceScreen)
        return adapter
    }

    override fun onDisplayPreferenceDialog(preference: Preference) {
        if (!preferenceGuard.showDialog(preference)) super.onDisplayPreferenceDialog(preference)
    }

    private fun currentProfile() = profiles.preferences.getString(ProfileStore.ACTIVE_ID_KEY, null) to
        profiles.preferences.getString(ProfileStore.ACTIVATION_KEY, null)

    private fun refreshProfileScreen() {
        if (!isAdded || preferenceScreen == null || renderedProfile == currentProfile()) return
        preferenceGuard.dismissStaleDialog()
        inflateSettings()
    }

    override fun onStart() {
        super.onStart()
        preferenceManager.sharedPreferences?.registerOnSharedPreferenceChangeListener(settingsListener)
        preferenceGuard.dismissStaleDialog()
        refreshProfileScreen()
        refreshSettingsOptions()
    }

    override fun onStop() {
        preferenceManager.sharedPreferences?.unregisterOnSharedPreferenceChangeListener(settingsListener)
        settingsHandler.removeCallbacksAndMessages(null)
        super.onStop()
    }

    private fun configureRemoteManagement() {
        findPreference<SwitchPreferenceCompat>(NativeRemoteManagementSettings.ENABLED_KEY)?.setOnPreferenceChangeListener { _, value ->
            val rootNative = preferenceManager.sharedPreferences?.let { getStringPrefValue(MvcPreference.BACKEND_MODE, it) == "ROOT_NATIVE" } == true
            if (!rootNative) return@setOnPreferenceChangeListener false
            val enabled = value == true
            if (enabled && !remoteManagement.hasPassword) {
                Toast.makeText(requireContext(), R.string.native_remote_password_required, Toast.LENGTH_LONG).show()
                showRemotePasswordDialog()
                return@setOnPreferenceChangeListener false
            }
            remoteManagement.enabled = enabled
            true
        }
        findPreference<Preference>("NATIVE_REMOTE_PASSWORD")?.setOnPreferenceClickListener { showRemotePasswordDialog(); true }
        findPreference<Preference>("NATIVE_REMOTE_CONNECTION")?.setOnPreferenceClickListener { showRemoteConnectionHelp(); true }
    }

    private fun refreshSettingsOptions() {
        val prefs = preferenceManager.sharedPreferences ?: return
        val tun = getStringPrefValue(MvcPreference.BACKEND_MODE, prefs) == "TUN"
        findPreference<Preference>(IPv6Policy.PREFERENCE_KEY)?.isVisible = !tun
        findPreference<Preference>(IPv6Policy.TUN_PREFERENCE_KEY)?.isVisible = tun
        findPreference<ThemePreference>(ThemeSettings.PREFERENCE_KEY)?.refresh()
        findPreference<DestinationRoutingPreference>("DESTINATION_ROUTING")?.refresh()
        findPreference<Preference>("APP_ROUTING")?.summary = runCatching {
            val label = when (appRouting.load().mode) {
                AppRoutingMode.EXCLUDE -> R.string.app_routing_mode_exclude
                AppRoutingMode.INCLUDE -> R.string.app_routing_mode_include
                AppRoutingMode.ALL -> R.string.app_routing_mode_all
            }
            getString(R.string.app_routing_summary_mode, getString(label))
        }.getOrElse { getString(R.string.app_routing_summary_invalid) }
        findPreference<Preference>("TUN_CONNECTION_SETTINGS")?.isVisible = tun
        findPreference<Preference>("NATIVE_CLIENT_SETTINGS")?.isVisible = !tun

        findPreference<Preference>("TLS_SETTINGS")?.setTitle(
            if (tun) R.string.section_tls else R.string.section_tls_probe
        )
        findPreference<Preference>(MvcPreference.SSL_SUITES.name)?.isVisible =
            prefs.getBoolean(MvcPreference.SSL_DO_SELECT_SUITES.name, false)

        if (!tun) {
            findPreference<SwitchPreferenceCompat>(NativeRemoteManagementSettings.ENABLED_KEY)?.isChecked =
                remoteManagement.enabled
            findPreference<Preference>("NATIVE_REMOTE_PASSWORD")?.setSummary(
                if (remoteManagement.hasPassword) R.string.native_remote_password_configured
                else R.string.native_remote_password_unset
            )
        }
    }

    private fun showRemotePasswordDialog() {
        if (!parentFragmentManager.isStateSaved &&
            parentFragmentManager.findFragmentByTag(NativeRemotePasswordDialogFragment.TAG) == null) {
            NativeRemotePasswordDialogFragment().show(parentFragmentManager, NativeRemotePasswordDialogFragment.TAG)
        }
    }

    private fun showRemoteConnectionHelp() {
        val addresses = runCatching {
            val core = NativeCoreRunner.active
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { it.isUp }
                .flatMap { network ->
                    val label = when {
                        core?.ownsTapInterface(network.name, network.index) == true -> getString(R.string.vpn_virtual_adapter)
                        network.name.startsWith("wlan") || network.name.startsWith("wifi") -> "Wi-Fi"
                        else -> return@flatMap emptyList()
                    }
                    network.inetAddresses.toList()
                    .filter { !it.isLoopbackAddress && !it.isAnyLocalAddress && !it.isMulticastAddress }
                    .filter { address ->
                        if (address !is Inet6Address) true else {
                            val firstByte = address.address[0].toInt() and 255
                            firstByte and 0xfe == 0xfc || firstByte and 0xe0 == 0x20
                        }
                    }
                    .map { address ->
                        val host = address.hostAddress.orEmpty().substringBefore('%')
                        val endpoint = if (address is Inet6Address) "[$host]:${NativeRemoteManagementSettings.MANAGEMENT_PORT}"
                            else "$host:${NativeRemoteManagementSettings.MANAGEMENT_PORT}"
                        getString(R.string.native_remote_interface_address, label, network.name, endpoint)
                    }
                }.distinct().sorted()
        }.getOrDefault(emptyList())
        val listing = if (addresses.isEmpty()) getString(R.string.native_remote_no_addresses) else addresses.joinToString("\n")
        val message = getString(R.string.native_remote_connection_help, listing)
        val dialog = MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.native_remote_connection_title)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok, null)
            .create()
        dialog.setOnShowListener { dialog.findViewById<android.widget.TextView>(android.R.id.message)?.setTextIsSelectable(true) }
        dialog.show()
    }

    private fun configureTlsOptions() {
        val supported = SSLContext.getDefault().supportedSSLParameters
        findPreference<DropDownPreference>(MvcPreference.SSL_VERSION.name)?.apply {
            val automatic = getString(R.string.pref_ssl_version_default)
            val protocols = supported.protocols.distinct()
            entries = (listOf(automatic) + protocols).toTypedArray()
            entryValues = (listOf("DEFAULT") + protocols).toTypedArray()
            summaryProvider = Preference.SummaryProvider<DropDownPreference> { item ->
                getString(R.string.pref_ssl_version_summary, item.value?.takeUnless { it == "DEFAULT" } ?: automatic)
            }
        }
        findPreference<MultiSelectListPreference>(MvcPreference.SSL_SUITES.name)?.apply {
            val suites = supported.cipherSuites.distinct().toTypedArray()
            entries = suites
            entryValues = suites
            summaryProvider = Preference.SummaryProvider<MultiSelectListPreference> { item ->
                val count = item.values.size
                if (count == 0) getString(R.string.pref_ssl_no_suites)
                else getString(R.string.pref_ssl_suites_selected, count)
            }
        }
    }
}
