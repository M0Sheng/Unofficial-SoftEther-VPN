# Native client functional scope

The Android app uses the pinned SoftEther Linux client command table from Cedar. This table describes the current integration. Linked upstream commands can depend on the device, server, permissions, and native runtime.

## App-managed connections

| Feature | TAP | TUN |
| --- | --- | --- |
| Native process | Rooted `vpnclient androidsvc` with a nonpersistent Ethernet interface | App-UID `vpnclient androidsvc` with a private frame channel and Android `VpnService` |
| Setup | App creates or configures logical NIC `home` and the selected account | App provisions a session-private NIC and account |
| Standard authentication | UTF-8 password | UTF-8 or GBK password |
| Server certificate | App preflight followed by native certificate checking | App preflight followed by native certificate checking |
| IPv4 | Android manages addressing on the Ethernet interface | App uses DHCP, ARP and gateway information before configuring TUN routes |
| IPv6 | Android manages addresses and routes on TAP. IPv6 frame forwarding can be switched off. | Optional SLAAC and Neighbor Discovery from the VPN-side network. TUN uses IPv4 DNS. |
| Application and address routing | Root per-UID and destination rules, subject to supported Android interfaces and network policy | Android package lists and IP routes |
| Transport | Default SoftEther TCP/TLS, with optional UDP acceleration. Native NAT-T/RUDP fallback is independent. | Direct TCP/TLS without NAT-T/RUDP fallback, with separate optional UDP acceleration |
| Notifications and status | Android foreground notification and native session/interface monitoring | Android foreground notification and packet-loop traffic counters |

## TAP management commands

The advanced screen runs the native client command table from a batch file. Supply required parameters and paths accessible to the rooted program. Use management-only mode to skip the app’s automatic login and connect the selected native account explicitly. The upstream startup sequence can restore saved NICs.

| Area | Commands or handlers | Integration |
| --- | --- | --- |
| Diagnostics | `About`, `Check`, `VersionGet` | Host and environment checks report device-specific results. |
| Accounts | `AccountList`, `AccountCreate`, `AccountSet`, `AccountGet`, `AccountDelete`, `AccountRename`, `AccountUsernameSet`, `AccountNicSet` | Standalone accounts and adapter bindings are managed in native core storage. |
| Password and anonymous authentication | `AccountPasswordSet`, `AccountAnonymousSet` | The command console can configure upstream authentication modes such as RADIUS and anonymous accounts. |
| Client certificates | `AccountCertSet`, `AccountCertGet` | Use absolute paths accessible to the native process for certificates and private keys. |
| Server certificates | `AccountServerCertEnable`, `AccountServerCertDisable`, `AccountServerCertSet`, `AccountServerCertDelete`, `AccountServerCertGet`, `CertList`, `CertAdd`, `CertDelete`, `CertGet` | Configure trust on each manually managed account before connecting. |
| Hardware security devices | `SecureList`, `SecureSelect`, `SecureGet`, `AccountSecureCertSet` | Upstream device enumeration is Windows-specific. Android hardware-token integration is unavailable. |
| Proxies | `AccountProxyNone`, `AccountProxyHttp`, `AccountProxySocks` | Configure on an independently managed account through the command console. |
| Connection parameters | `AccountDetailSet`, `AccountRetrySet`, `AccountEncryptEnable`, `AccountEncryptDisable`, `AccountCompressEnable`, `AccountCompressDisable` | Upstream session settings apply to manually managed accounts. The app’s managed account uses its own settings. |
| Adapter settings | `NicCreate`, `NicDelete`, `NicGetSetting`, `NicSetSetting`, `NicEnable`, `NicDisable`, `NicList` | The managed `home` adapter has a session-specific Android interface. Other NICs use upstream names and require their own Android network integration. |
| Session status | `AccountConnect`, `AccountDisconnect`, `AccountStatusGet` | Account status and actual interface/address state are distinct. |
| Autostart and interchange | `AccountStartupSet`, `AccountStartupRemove`, `AccountExport`, `AccountImport` | The owner defers saved automatic login. Batch import/export uses paths accessible to the native program. The app’s profile picker handles `.vpn` files independently. |
| Keepalive | `KeepEnable`, `KeepDisable`, `KeepSet`, `KeepGet` | Available through the native core. The Android service selects the underlying network. |
| Remote management | `RemoteEnable`, `RemoteDisable`, `PasswordSet` | Requires the phone’s opt-in and a separate remote credential. Loopback authentication always uses the app’s per-run secret. See [management interface](README.md#management-interface). |
| Certificates and throughput utilities | `MakeCert`, `MakeCert2048`, `TrafficClient`, `TrafficServer` | Native handlers are exposed as batch commands. Output files require accessible paths. Throughput listeners belong to the explicitly invoked utility. |
| Desktop-only interface | `NicUpgrade`, `AccountStatusShow`, `AccountStatusHide` | The Android app uses the kernel TAP and its own foreground service and notification. Desktop driver upgrades and popup windows are unavailable on Android. |

The Android console takes complete command lines with parameters. Interactive prompts and desktop terminal history are unavailable. [Pinned command table](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/blob/ed17437af9719ac66acab30faa29e375d613c35f/src/Cedar/Command.c) · [Upstream `vpncmd` manual](https://www.softether.org/4-docs/1-manual/6/6.5)
