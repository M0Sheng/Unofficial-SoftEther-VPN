# Unofficial SoftEther VPN

An independent Android client by M0Sheng for connecting to a SoftEther VPN server you or your organization operate. Bring your own server address and account. [简体中文](README_zh.md)

The app requires **Android 16 or later**. Choose English, Simplified Chinese, or Japanese in **Settings → Appearance & shortcuts → App language**.

The [v1.8.69 prerelease](https://github.com/M0Sheng/Unofficial-SoftEther-VPN/releases/tag/v1.8.69) includes five signed APKs and the SHA-256 checksums. Choose the APK for your device architecture (`armeabi-v7a`, `arm64-v8a`, `x86`, or `x86_64`), or use `-universal.apk` for all four. The app ID is `io.github.m0sheng.unofficialsoftethervpn`.

## Move from an earlier build

To move profiles from the earlier application ID, disconnect the old app and choose **Export .vpn** from the menu for each profile. In the new app, choose **Profiles → Import**, then enter any required password or import your client certificate and private key again. Grant Android VPN access for TUN or Root access for TAP, and reapply shared settings such as application routing.

## Connect

1. Install the signed APK downloaded above.
2. On **Home**, tap **Open Profiles** to add a profile or import a supported profile in `.vpn` format. Enter the server address and port to look up available virtual Hubs. Choose a Hub or enter its name, then fill in the credentials. New profiles start with port `443`. The port menu also offers `8888`, `992`, `5555`, and custom entry.
3. New profiles use **TUN** by default. Accept Android’s VPN request when prompted. For Layer 2 access, choose **TAP** in **Settings → Access method** on a compatible device and grant root to the app.
4. Tap **Connect** on **Home**. Review the VPN data disclosure when prompted. If the app asks you to approve a server certificate, verify it with the server administrator. **Network details** shows the assigned addresses, routes, interface, and the live session’s TLS, data encryption, and server certificate information.

| Access method | Requirements | Traffic |
| --- | --- | --- |
| TUN (default for new profiles) | Android `VpnService` consent | Layer 3. Carries IPv4 and optional IPv6. Needs an IPv4 DHCP lease from the VPN-side network. |
| TAP | Root and compatible Android Ethernet integration | Layer 2. Carries Ethernet frames, including ARP, broadcast, and multicast. Android configures addresses and routes. |

On some systems, such as HyperOS, the Wi-Fi icon may show an exclamation mark when TAP becomes the system default network, even while traffic works. See **Home → Network details** for Android network validation.

Both modes use the native SoftEther v4.44-9807-rtm core. The Rust TUN engine batches IP and Ethernet I/O and handles IPv4 DHCP/ARP and IPv6 SLAAC and neighbor discovery. Kotlin manages the Android VPN interface, routing preferences, and the app. App-managed connections default to TCP/TLS with UDP acceleration disabled. LAN access across subnets and access to the public internet depend on the VPN-side gateway, routes, and server configuration. The client adds no NAT.

When Android switches between Wi-Fi and mobile data, app-managed TAP and TUN sessions reconnect automatically after the new network becomes usable. Existing transfers may pause while the session is rebuilt. If the connection fails, **Home** shows the reason and the SoftEther error code when available. Tap **Reconnect** to try again.

## Profiles and certificates

Create, rename, copy, edit, and delete profiles from **Profiles**. Server, Hub, credentials, access method, IPv6 settings, and destination rules are saved per profile. Profile-specific options such as the access method are saved immediately when changed in **Settings** and take effect on the next connection. The app list, theme, and notification settings are shared.

Certificate trust belongs to each profile and server endpoint. App-managed login checks the server certificate before sending VPN credentials. If a certificate needs approval, check its identity and fingerprint through a trusted channel. A replaced certificate needs fresh verification. Manage stored trust from **Profiles → Edit → Server certificate**.

The profile editor looks up the Hubs the server advertises after you enter its address and port. Open the list beside the Hub field to select an entry, or enter a Hub name manually. You can verify and remember the server certificate during lookup. For a new address or port, save the profile to keep that certificate for VPN connections.

TAP and TUN support anonymous, standard password, RADIUS or NT domain, and client certificate authentication. Certificate authentication takes an X.509 certificate and a matching RSA private key. The app encrypts that key using Android Keystore. The Android SoftEther core does not support smart-card sign-in.

The `.vpn` importer handles direct connections. Exports include connection settings and omit usable user credentials. Supply the credentials on the device according to the selected authentication type. The file can still identify the server, Hub, and username.

## Routing and IPv6

**Application routing** defaults to **All apps** and **Destination routing** defaults to **All addresses**. A blacklist sends listed apps or destinations over the original network. A whitelist sends only listed entries through the VPN. Both rules apply when selecting a route. Apps that share a UID follow the same application rule.

Destination lists accept IP addresses, CIDR networks, and exact domain names. Domain rules use a snapshot resolved on the original network at connection time. Reconnect after editing routes or to refresh DNS answers. For names resolvable only inside the VPN, enter the corresponding IP address or CIDR instead.

IPv6 forwarding is off by default for TAP and TUN. Profiles with a saved IPv6 setting use that setting. With forwarding enabled, TAP relies on Android and the VPN-side network to configure IPv6. TUN uses SLAAC and IPv4 DNS. The VPN-side network must provide usable Router Advertisements and routes. On TAP, Root routing depends on the Android implementation and firmware. See [Root routing notes](docs/ROOT_ROUTING.md) for system requirements and limitations.

## Appearance, notifications, logs, and TAP management

- Open the theme settings to choose a light, dark, or system theme and configure Material 3 dynamic colors or an accent color.
- Add the VPN tile to Android Quick Settings to connect and disconnect. Long-press it to open the app. Enable **Show traffic in the notification** to show upload and download rates once the VPN connects.
- In **Settings → Support & information → Logs**, turn on **Collect diagnostic logs** to investigate connection, TLS, address assignment, or routing failures. Captured events stay in memory while the app process runs, even after you stop collecting. Use **Export** to save a copy.
- In TAP mode, **vpncmd** manages the standalone native client accounts. Remote management is off by default and requires a separate password. Use `vpncmd PHONE_IP /CLIENT` from a trusted LAN or encrypted connection to reach the management service on TCP `9930`. The management protocol itself is unencrypted.

## Support and privacy

Report issues with the app version, Android version, device model, access method, and error code or reproduction steps. Remove credentials, server addresses, and other private network details from anything you share. [GitHub Issues](https://github.com/M0Sheng/Unofficial-SoftEther-VPN/issues)

VPN traffic goes to the server you choose. Its operator handles routing and any server-side records. Diagnostic collection is off by default. Logs and profile exports can contain server and network details.

## Credits and licenses

See [LICENSE](LICENSE), [SoftEther’s license](SOFTETHER_LICENSE), the [project notices](NOTICE), and [native dependency licenses](native-core-source/licenses/). SoftEther and its logo are marks of their respective owners. This independent app is unaffiliated with SoftEther Corporation.
