package kittoku.mvc.preference

// These names are the existing on-disk keys and are used by exported profiles.
internal enum class MvcPreference {
    HOME_HOSTNAME, HOME_HUB, HOME_USERNAME, HOME_PASSWORD, AUTH_PASSWORD_ENCODING,
    BACKEND_MODE, ROUTE_MODE, LAN_ROUTES,
    SSL_PORT, SSL_VERSION, SSL_DO_SELECT_SUITES, SSL_SUITES,
    ETHERNET_MTU, ETHERNET_MAC_ADDRESS, UDP_ENABLE_ACCELERATION,
    HOME_CONNECTOR, HOME_STATUS, UDP_STATUS,
}
