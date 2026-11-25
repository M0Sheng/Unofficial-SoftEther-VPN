# Google Play 商店资料草稿

以 GitHub 预发布版本 1.8.66（246）为基线，软件包为 `io.github.m0sheng.unofficialsoftethervpn`。提交前将说明和素材与待审核版本对齐。

## 简体中文（zh-CN）

### 应用名称

Unofficial SoftEther VPN

### 简短说明

连接自建 SoftEther VPN 服务器，访问远程内网。支持免 Root TUN、Root TAP 与分流规则。

### 完整说明

在 Android 手机上使用现有的 SoftEther VPN 账户，访问家中、办公室或其他获得授权的远程网络。连接需要服务器地址、端口、虚拟 Hub 和可用账号。

- TUN 使用 Android 的 VpnService 建立三层隧道，支持 IPv4 和可选 IPv6 转发，免 Root。
- TAP 在已授予 Root 的设备上建立二层连接，支持虚拟以太网接口、局域网广播和组播。
- 按应用或目标地址选择经过 VPN 的流量。地址规则可使用 IP、CIDR 网段和精确域名。
- 管理多份连接配置和各自的服务器证书，并可导入、导出 `.vpn` 配置文件。
- 使用快捷设置开关连接，在连通后查看流量通知，需要排查问题时可手动采集和导出诊断日志。

支持 Android 16 及以上的 ARM 和 x86 设备。由 M0Sheng 独立维护。SoftEther 商标归其权利人所有。

### 更新说明

首次公开发行。可通过 TUN 或 TAP 连接自备的 SoftEther VPN 服务器，按应用或目标地址配置分流。

## English (en-US)

### App name

Unofficial SoftEther VPN

### Short description

Connect to your SoftEther VPN server and control which apps use the tunnel.

### Full description

Connect to your own or an authorized SoftEther VPN server from Android. You need a server address, port, virtual hub and VPN account from the network administrator.

- TUN uses Android's VpnService for Layer 3 IPv4 and optional IPv6 forwarding without root.
- TAP provides a Layer 2 Ethernet connection with LAN broadcasts and multicast on devices with granted root access.
- Choose which apps and destinations use the VPN. Destination rules support IP addresses, CIDR prefixes and exact domain names.
- Save multiple profiles with separate server certificates. Import and export SoftEther `.vpn` profiles.
- Connect from Quick Settings, view traffic once connected, and collect and export diagnostics when needed.

For ARM and x86 devices running Android 16 or later. Independently maintained by M0Sheng. SoftEther is a trademark of its owner.

### Release notes

First public release. Connect to your own SoftEther VPN server using TUN or TAP and route traffic by app or destination.

## 图片和视频

- 使用[独立图标](../../design/BRANDING.md)制作 512 × 512 应用图标和 1024 × 500 宣传图。
- 参考截图包括[路由设置](assets/phone-settings-zh-CN.png)和[接入方式选择](assets/phone-access-modes-zh-CN.png)，已裁去系统状态栏。补拍连接状态时使用专用审核配置。
- 单独拍摄权限申报视频，演示打开应用、阅读 VPN 使用说明、授权、连接、前台通知、访问测试资源和停止。商店宣传视频可按需补充。 [Google Play 商店展示资源要求](https://support.google.com/googleplay/android-developer/answer/9866151)
