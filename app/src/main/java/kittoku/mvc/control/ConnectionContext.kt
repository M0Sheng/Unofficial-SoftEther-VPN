package kittoku.mvc.control

import android.content.SharedPreferences
import android.net.Network
import kittoku.mvc.R
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.nativecore.NativeAuthMode
import kittoku.mvc.nativecore.NativeAuthentication
import kittoku.mvc.network.IPv6Policy
import kittoku.mvc.network.parseAdditionalLanRoutes
import kittoku.mvc.preference.MvcPreference
import kittoku.mvc.preference.accessor.getBooleanPrefValue
import kittoku.mvc.preference.accessor.getIntPrefValue
import kittoku.mvc.preference.accessor.getSetPrefValue
import kittoku.mvc.preference.accessor.getStringPrefValue
import kittoku.mvc.profile.ProfileStore
import kittoku.mvc.routing.TunDestinationConfiguration
import kittoku.mvc.routing.TunDestinationMode
import kittoku.mvc.routing.TunDestinationSettings
import kittoku.mvc.routing.parseTapDestinationRules
import kittoku.mvc.service.SoftEtherVpnService
import kittoku.mvc.tls.CertificateTrustStore
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope

internal class ConnectionContext(
    val service: SoftEtherVpnService,
    val scope: CoroutineScope,
    val handler: CoroutineExceptionHandler,
    val sessionId: String,
    private val prefs: SharedPreferences,
    val backendMode: String,
    val profileId: String,
    profiles: ProfileStore,
    val excludedUnderlay: Network? = null,
) {
    private fun text(key: MvcPreference) = getStringPrefValue(key, prefs)
    private fun enabled(key: MvcPreference) = getBooleanPrefValue(key, prefs)
    private val tap = backendMode == BackendModePolicy.ROOT_NATIVE
    val nativeManagementOnly = tap && prefs.getBoolean("NATIVE_MANAGEMENT_ONLY", false)
    val forwardIpv6 = prefs.getBoolean(IPv6Policy.PREFERENCE_KEY, IPv6Policy.DEFAULT_FORWARDING)
    val tunIpv6Forward = !tap && prefs.getBoolean(IPv6Policy.TUN_PREFERENCE_KEY, IPv6Policy.DEFAULT_FORWARDING)
    val serverHostname = text(MvcPreference.HOME_HOSTNAME)
    val serverPort = getIntPrefValue(MvcPreference.SSL_PORT, prefs)
    val serverHubName = text(MvcPreference.HOME_HUB)
    val clientUsername = text(MvcPreference.HOME_USERNAME)
    private val authMode = if (nativeManagementOnly) NativeAuthMode.ANONYMOUS
        else NativeAuthMode.from(prefs.getString("HOME_AUTH_TYPE", null))
    val clientPassword = if (authMode.usesPassword) text(MvcPreference.HOME_PASSWORD) else ""
    private val passwordEncoding = if (authMode == NativeAuthMode.STANDARD_PASSWORD) {
        BackendModePolicy.passwordEncoding(backendMode, if (tap) null else text(MvcPreference.AUTH_PASSWORD_ENCODING))
    } else "UTF-8"
    val authentication = NativeAuthentication.from(authMode, clientPassword, passwordEncoding) {
        prefs.getString(it, null).orEmpty()
    }
    val sslVersion = text(MvcPreference.SSL_VERSION)
    val cipherSuites: Set<String>? = if (enabled(MvcPreference.SSL_DO_SELECT_SUITES))
        getSetPrefValue(MvcPreference.SSL_SUITES, prefs) else null
    val useUdpAcceleration = enabled(MvcPreference.UDP_ENABLE_ACCELERATION)
    val destinationConfiguration: TunDestinationConfiguration? = TunDestinationSettings.effective(service, prefs, tap)
    val legacyLanOnly = destinationConfiguration == null && text(MvcPreference.ROUTE_MODE) == "LAN"
    val legacyLanRoutes = if (legacyLanOnly) parseAdditionalLanRoutes(text(MvcPreference.LAN_ROUTES)) else emptyList()
    val tunRoutingLabel = when (destinationConfiguration?.mode) {
        TunDestinationMode.EXCLUDE -> R.string.destination_mode_exclude
        TunDestinationMode.INCLUDE -> R.string.destination_mode_include
        TunDestinationMode.ALL -> R.string.destination_mode_all
        null -> if (legacyLanOnly) R.string.tun_vpn_subnet_routes else R.string.tun_ipv4_default_route
    }
    val tunAllowsOriginalIpv6WhenOff = destinationConfiguration?.mode?.let { it == TunDestinationMode.INCLUDE }
        ?: legacyLanOnly
    val tunMtu = if (!tap && useUdpAcceleration) {
        // IPv4/UDP plus the SoftEther acceleration header, nonce/tag and Ethernet header.
        (getIntPrefValue(MvcPreference.ETHERNET_MTU, prefs) - 93).coerceIn(if (tunIpv6Forward) 1280 else 68, 1500)
    } else 1500
    val tunMac: ByteArray
    val certificateSha256: String
    @Volatile var underlyingNetwork: Network? = null

    init {
        if (tap) parseTapDestinationRules(requireNotNull(destinationConfiguration), forwardIpv6)
        if (!nativeManagementOnly) {
            require(serverHostname.isNotBlank() && '/' !in serverHostname) { service.getString(R.string.network_runtime_error_server_hostname_format) }
            require(serverPort in 1..65535) { service.getString(R.string.error_invalid_port) }
            require(serverHubName.isNotBlank() && clientUsername.isNotBlank()) { service.getString(R.string.network_runtime_error_missing_hub_and_username) }
            require(clientUsername.all { it.code in 1..127 }) { service.getString(R.string.network_runtime_error_vpn_username_ascii) }
            authentication.validate()
            if (!tap && destinationConfiguration == null) {
                require(text(MvcPreference.ROUTE_MODE) in setOf("LAN", "FULL")) { service.getString(R.string.network_runtime_error_legacy_route_mode) }
            }
        }
        certificateSha256 = if (nativeManagementOnly) "" else
            CertificateTrustStore(service).savedPin(profileId, serverHostname, serverPort)
        tunMac = if (tap) ByteArray(0) else readTunMac(profiles.readOrCreateTunMac(profileId))
    }

    private fun readTunMac(address: String): ByteArray {
        val stored = address.filterNot { it == ':' || it == '-' }
        require(stored.length == 12 && stored.all { it.digitToIntOrNull(16) != null }) { service.getString(R.string.network_runtime_error_virtual_adapter_mac_invalid) }
        val mac = stored.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        require((mac[0].toInt() and 1) == 0 && mac.any { it != 0.toByte() }) { service.getString(R.string.network_runtime_error_virtual_adapter_mac_unicast) }
        return mac
    }
}
