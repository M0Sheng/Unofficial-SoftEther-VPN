package kittoku.mvc.network

/** Both access methods use separate, opt-in IPv6 settings per profile. */
internal object IPv6Policy {
    const val PREFERENCE_KEY = "VPN_FORWARD_IPV6"
    const val TUN_PREFERENCE_KEY = "TUN_FORWARD_IPV6"
    const val DEFAULT_FORWARDING = false
}
