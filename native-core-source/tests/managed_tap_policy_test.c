/* Runs the actual native input validators without Android, TAP, root, or
 * networking. The Android kernel creation marker still needs device testing. */
#include "homevpn_managed_tap.h"
#include "homevpn_legacy_instance.h"
static int checks;
#define CHECK(condition) do { checks++; if (!(condition)) return checks; } while (0)
int mainCRTStartup(void) {
    const char *valid_names[] = { "eth0", "eth9", "eth10", "usb0", "usb999", "eth123456789012", "usb123456789012" };
    const char *invalid_names[] = {
        0, "", "eth", "usb", "eth-1", "usb+1", "Eth1", "USB1", "vpn_home", "wlan0", "rmnet0",
        "eth1 ", " eth1", "eth1\n", "eth1/2", "eth1:2", "eth%d", "eth1;id", "eth1$()", "eth\xef\xbc\x91",
        "eth1234567890123", "usb1234567890123", "eth012345678901234567890123456789", "e", "et", "u", "us"
    };
    for (unsigned int i = 0; i < sizeof(valid_names) / sizeof(valid_names[0]); i++) CHECK(homevpn_managed_tap_name_valid(valid_names[i]));
    for (unsigned int i = 0; i < sizeof(invalid_names) / sizeof(invalid_names[0]); i++) CHECK(!homevpn_managed_tap_name_valid(invalid_names[i]));
    const char *token = "01234567-89ab-cdef-0123-456789abcdef";
    CHECK(homevpn_managed_tap_token_valid(token));
    CHECK(!homevpn_managed_tap_token_valid(0));
    CHECK(!homevpn_managed_tap_token_valid(""));
    CHECK(!homevpn_managed_tap_token_valid("01234567-89AB-cdef-0123-456789abcdef"));
    CHECK(!homevpn_managed_tap_token_valid("01234567-89ab-cdef-0123-456789abcdeg"));
    CHECK(!homevpn_managed_tap_token_valid("01234567-89ab-cdef-0123-456789abcde"));
    CHECK(!homevpn_managed_tap_token_valid("01234567-89ab-cdef-0123-456789abcdef0"));
    char altered[38];
    for (int i = 0; i < 37; i++) altered[i] = token[i];
    altered[37] = 0;
    /* Every non-hex/hyphen byte and every early terminator must be rejected. */
    for (int i = 0; i < 36; i++) {
        char original = altered[i];
        altered[i] = '/'; CHECK(!homevpn_managed_tap_token_valid(altered));
        altered[i] = 0; CHECK(!homevpn_managed_tap_token_valid(altered));
        altered[i] = original;
    }
    CHECK(homevpn_legacy_instance_name_valid(".VPN-0123456789"));
    CHECK(homevpn_legacy_instance_name_valid(".VPN-ABCDEF0123"));
    CHECK(homevpn_legacy_instance_name_valid(".VPN-abcdef0123"));
    const char *invalid_locks[] = {
        0, "", ".", ".V", ".VP", ".VPN", ".VPN-", "VPN-0123456789", ".vpn-0123456789",
        ".VPN-012345678", ".VPN-01234567890", ".VPN-012345678g", ".VPN-0123456789/", ".VPN-0123456789\n",
        ".VPN-0123456789.lock", "../.VPN-0123456789", "androidsvc.lock"
    };
    for (unsigned int i = 0; i < sizeof(invalid_locks) / sizeof(invalid_locks[0]); i++) CHECK(!homevpn_legacy_instance_name_valid(invalid_locks[i]));
    return 0;
}
