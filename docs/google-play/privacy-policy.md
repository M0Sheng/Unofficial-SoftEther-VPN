# Unofficial SoftEther VPN 隐私政策 / Privacy Policy

发布草稿。上线前由发布者填写下列信息并确认与最终商店版本及 Google Play 开发者资料一致。

| 项目 / Field | 待填写 / To complete |
| --- | --- |
| 发布者或负责实体 / Publisher or responsible entity | `[PLAY_DEVELOPER_NAME]` |
| 隐私联系邮箱 / Privacy contact email | `[PRIVACY_EMAIL]` |
| 生效日期 / Effective date | `[YYYY-MM-DD]` |
| 公开政策网页 / Public policy page | `[PUBLIC_PRIVACY_POLICY_URL]` |

## 简体中文

本政策适用于由 `[PLAY_DEVELOPER_NAME]` 发布的 Unofficial SoftEther VPN（`io.github.m0sheng.unofficialsoftethervpn`）。该应用供你连接自己管理或有权访问的 SoftEther VPN 服务器。VPN 账号由你选择的服务器管理员分配。

### 设备上的信息

- 连接配置包含你填入的服务器地址、端口、虚拟 Hub、账号和密码，以及保存在配置中的服务器证书和网络选项。配置保存在 Android 应用私有存储中。
- 分应用路由读取本机安装的应用及其标识，以展示应用列表并将路由规则应用到对应应用。应用列表在设备上处理。
- 诊断采集默认关闭。你可以在日志页开启采集，记录设备型号、Android 和应用版本、服务器地址、虚拟 Hub、网络地址、应用包名、连接状态和错误等信息。近期记录暂存在应用内存中，应用进程退出时清除。你也可以在日志页随时清空记录，或通过系统文件选择器手动导出。
- 导出的 `.vpn` 文件可能包含服务器地址、虚拟 Hub、用户名、证书和设置。导出时省略 VPN 密码，导入后需要重新填写。导出日志和配置时，由你选择保存位置及后续分享对象。

### 连接过程中发送的信息

- TUN 使用 Android VpnService 捕获符合当前路由规则的 IP 数据包并转发至你选择的 VPN 服务器。TAP 在你授予 Root 后转发虚拟以太网接口上的流量。首页使用已保存配置发起的连接启用隧道加密和服务器证书检查。连接涉及 VPN 账号认证、网络端点和协议所需的连接元数据。
- VPN 服务器负责接收、转发和管理该连接。服务器运营者可看到连接所需的网络信息，以及目的地址和未受应用层端到端加密保护的内容。其处理、留存和删除方式由服务器运营者决定。域名解析会向所用网络的 DNS 服务发出查询，部分域名分流规则会在连接时解析。
- TAP 中 SoftEther 的 NAT 穿透，以及启用后的 UDP 加速，可能与 SoftEther 上游发现服务交换网络地址、端口及连接建立元数据。TAP 高级管理允许对手动账户设置证书检查和加密选项，自行配置的代理、连接保活目标和其他服务器也会收到所选功能所需的请求。
- TAP 的电脑远程管理需在手机上主动启用并设置独立口令。它使用 SoftEther 的旧版管理协议，该管理流量没有独立的 TLS 加密层。建议在可信的 VPN 或局域网内使用。
- 当前应用的连接由选定的服务器处理，诊断日志由用户在设备上导出。你主动向支持方提供日志时，支持方会使用你提供的内容处理该请求。

### 保留、删除和联系

设备上的连接配置随你删除对应配置或清除应用数据而删除。你可以单独清除应用日志。系统文件选择器保存的导出件由你管理。存放在服务器上的账户和记录请联系对应服务器的运营者。关于本应用的数据处理、访问或删除请求，请联系 `[PRIVACY_EMAIL]`。

## English

This policy applies to Unofficial SoftEther VPN (`io.github.m0sheng.unofficialsoftethervpn`), published by `[PLAY_DEVELOPER_NAME]`. The app connects to a SoftEther VPN server you administer or are authorized to use. Your server administrator provides the VPN account.

### Information on your device

- Connection profiles store the server address, port, virtual hub, username and password you enter, along with saved server certificates and network options. Profiles are kept in Android app-private storage.
- Per-app routing reads installed app information and package identifiers so you can choose apps and the phone can apply the routing rules. The app list is processed on the device.
- Diagnostic collection is off by default. You can turn it on from the Logs screen to record information such as the device model, Android and app versions, VPN server address, virtual hub, network addresses, app package names, connection events and errors. Recent events stay in memory while the app process runs. You can clear them on the Logs screen or manually export a copy using the system file picker.
- Exported `.vpn` profiles can include the endpoint, virtual hub, username, certificate and settings. The VPN password is omitted and must be entered after import. You choose where exports are stored and who receives them.

### Information sent when you connect

- TUN uses Android VpnService to route IP packets selected by your rules to the configured VPN server. TAP forwards traffic through a virtual Ethernet interface after you grant root access. Connections started from Home using a saved profile enable tunnel encryption and server certificate checks. A connection involves VPN account authentication, network endpoints and protocol metadata needed to establish the session.
- The server operator receives and routes traffic. The operator can see connection information, destinations and payloads without separate application-level end-to-end encryption. The server operator determines how server-side information is handled, retained and deleted. Domain resolution makes queries to the selected network's DNS service, including resolution of exact-domain routing rules.
- SoftEther NAT traversal in TAP, and UDP acceleration when enabled, may exchange network addresses, ports and setup metadata with upstream SoftEther discovery services. TAP advanced management gives you control over certificate checks and encryption for manually managed accounts. Proxies, keepalive targets and other hosts you configure receive requests for the features you use.
- Remote VPN client management from a computer must be enabled on the phone with a separate password. It uses SoftEther's legacy management protocol without a separate TLS layer. Use it over a trusted VPN or local network.
- The connection is handled by the designated server. Diagnostics are exported from the device at your request. If you choose to send logs to support, the provided material is used to handle your support request.

### Retention, deletion and contact

Delete a connection profile or clear app data to remove stored profiles from the device. Use the Logs screen to remove diagnostics. Manage exported copies in the location you selected. Contact the server operator to request removal of server-side accounts or records. Contact `[PRIVACY_EMAIL]` with app privacy questions or requests to access or delete information.
