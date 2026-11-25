# Google Play 上架准备

本目录用于 Unofficial SoftEther VPN（软件包 `io.github.m0sheng.unofficialsoftethervpn`）的上架准备。收录[商店资料](store-listing.md)、[隐私政策草稿](privacy-policy.md)和权限申报所需的技术说明。联系信息和商店素材以发布者确认的内容为准。

## 构建与上传包

1. 在 GitHub 仓库配置 `ANDROID_KEYSTORE_B64` 和 `ANDROID_SIGNING_PROPERTIES_B64`。
2. 手动运行 **Build Android APK** 并勾选 `build_play_bundle`。 [GitHub Actions](https://github.com/M0Sheng/Unofficial-SoftEther-VPN/actions/workflows/pre-release-apk.yml)
3. 从该次运行的 `Unofficial-SoftEther-VPN-Play-bundle` 下载已签名的 AAB，上传 Play Console。可从同一运行的 `Unofficial-SoftEther-VPN-all-abis` 下载通用 APK 或设备对应的架构 APK，供安装验证。

最低和目标版本都是 Android 16（API 36）。构建包含 `armeabi-v7a`、`arm64-v8a`、`x86` 和 `x86_64`。

Play App Signing 会生成并签发面向设备的 APK。区分上传密钥与面向用户的应用签名密钥。若要让 Play 版本覆盖已自装版本，首次配置时请核对最终分发签名与现有 APK 的关系，并备份密钥库及密码。 [Play App Signing](https://developer.android.com/studio/publish/app-signing)

提交 AAB 前可用 bundletool 验证设备分包，并在使用 16 KiB 内存页的设备或模拟器验证首次启动、授权、连接与断开。 [16 KB 页面兼容说明](https://developer.android.com/guide/practices/page-sizes)

自动管理的配置会验证服务器证书并启用加密。当前完整功能候选包包含「TAP 高级管理 → vpncmd 命令」，其中的 `AccountEncryptDisable` 能更改原生账号的加密设置。电脑远程管理也可操作原生账号。生产发行前应决定如何保证手动配置连接的流量同样加密。 [SoftEther 命令说明](https://www.softether.org/4-docs/1-manual/6/6.5) [VpnService 政策](https://support.google.com/googleplay/android-developer/answer/12564964)

## App Content 申报草稿

### VpnService

主要用途选核心 VPN 功能。TUN 使用 Android VpnService 建立 IP 层隧道，将用户配置的应用与目的地址流量发往选定的 SoftEther VPN 服务器。用户在首页或快捷设置中启动 VPN，可随时停止。自动恢复仅对应用户已发起的连接。首次使用说明应告知流量、使用目的和接收方，并由用户主动确认后再请求 Android VPN 授权。按申报表要求提供每段 90 秒以内的视频，展示实际使用以及完整告知与确认。 [VpnService 申报和视频要求](https://support.google.com/googleplay/android-developer/answer/12564964)

### 前台服务

当前 Manifest 使用 `FOREGROUND_SERVICE_SPECIAL_USE`。`SoftEtherVpnService` 在用户主动连接期间维护隧道，切到后台仍需收发网络数据，并显示可停止连接的系统通知。视频演示启动、已连接、通知中的停止入口、实际断开，并说明中止前台服务会终止 VPN。 [前台服务申报](https://support.google.com/googleplay/android-developer/answer/13392821)

### 安装应用列表

当前 Manifest 声明 `QUERY_ALL_PACKAGES`。分应用路由需要把选择的包名对应到 Android UID，并识别与同一 UID 关联的应用。现有列表包括系统和没有启动入口的应用。清点在设备上进行，用于列表和包级路由。申报时展示白名单、黑名单和系统应用选项，并说明已评估范围更窄的包可见性方案。是否批准由 Play 审核决定。若审核不能接受当前范围，评估缩窄可见范围后的功能取舍与新版构建。 [扩大软件包可见性的要求](https://support.google.com/googleplay/android-developer/answer/10158779)

### 隐私政策与 Data Safety

将[隐私政策](privacy-policy.md)补齐发布者、联系邮箱和生效日期，发布到可直接访问且无需登录的网页，在 Play Console 和应用内提供入口。应用内首次使用说明和政策入口应能分别查阅。发布者需按最终 AAB 和实际服务器关系完成 Data Safety 表单。 [用户数据政策](https://support.google.com/googleplay/android-developer/answer/10144311) [应用审核资料](https://support.google.com/googleplay/android-developer/answer/9859455)

| 数据流 | 本地核对结果 |
| --- | --- |
| 连接配置和证书 | 保存在应用私有存储。登录认证及协议字段会发送到用户选定服务器。导出的 `.vpn` 文件可能带用户名、地址和证书。 |
| 应用清单 | 供设备本地应用路由使用。清单属于 Google Play 敏感用户数据的范围。 |
| VPN 及 DNS | 选定流量经加密隧道到达用户服务器。DNS 解析根据配置使用网络的解析服务。服务器端留存和访问由服务器运营者决定。 |
| 诊断日志 | 默认关闭，用户可在日志页开启采集。近期记录在内存中滚动保留，可清空或手动导出。导出文件可包含端点、设备与网络信息。 |
| TAP 协议兼容 | TAP 的 SoftEther NAT 穿透和可选 UDP 加速可与上游服务交换网络与连接元数据。高级管理中用户自行配置的代理或保活服务也要纳入核对。电脑远程管理是另行启用的旧版管理协议，链路本身没有 TLS。 |

Google Play 将应用向设备外传输的数据纳入收集定义，并规定了仅在设备上处理和严格端到端加密等例外。用户明确发起且合理预期的第三方传输属于共享项的例外。按最终构建的实际端点、接收方和留存方式逐项核对收集、共享和传输加密。VPN 服务端可读取的流量不能仅凭隧道加密而按端到端加密处理。 [填写 Data Safety 表](https://support.google.com/googleplay/android-developer/answer/10787469)

## 提供给审核人员的访问说明

使用独立于个人内网的临时审核配置。审核账号只允许访问一项没有个人信息的测试资源，在审核期内保持可用。登录信息填写在 Play Console 的 App access 栏位。

> Open the app on a device running Android 16 or later. In **Profiles (配置)**, create a profile using the review server address, TCP port, virtual hub, username and password supplied in App access. Save and select the profile. Open **Settings (设置) → Access method (接入方式)** and select **TUN** for this profile. Return to **Home (首页)** and tap **Connect (连接)**. Read and accept the VPN disclosure, then approve Android's VPN request. Confirm the app shows Connected (已连接). Open the test URL supplied in App access and confirm that it loads. Tap **Disconnect (断开)** on Home or in the ongoing notification.

在 App access 中提供实际服务器值和测试 URL。建议审核服务器使用匹配域名、系统认可且证书链完整的证书；如需验证自签名场景，应提供可独立核对的服务器证书指纹和明确操作步骤。TUN 审核路径可在普通设备完成。TAP 是附加功能，应用说明要交代 Root 依赖。 [App access](https://support.google.com/googleplay/android-developer/answer/9859455)

## 发布前待确认

- 使用开发者账号创建应用和选定 Play App Signing 方案。2023 年 11 月 13 日后创建的个人开发者账号须完成至少 12 名测试者连续加入封闭测试 14 天，再申请生产访问。 [新个人账号测试要求](https://support.google.com/googleplay/android-developer/answer/14151465)
- 使用 Unofficial SoftEther VPN 作为商店名称，使用本项目的 Tabler 图标制作素材。保留 SoftEther 兼容性的说明和第三方署名。图标来源见[设计文档](../../design/BRANDING.md)。 [知识产权政策](https://support.google.com/googleplay/android-developer/answer/9888072) [商店资料政策](https://support.google.com/googleplay/android-developer/answer/9898842)
- 用最终提交包复核各连接路径。应用托管的连接启用加密和证书检查。TAP 手动账户可在高级管理里修改相应设置，电脑远程管理使用独立的旧版协议。提交前确认这些可选路径如何满足 Play 的 VPN 传输加密要求。 [VpnService 政策](https://support.google.com/googleplay/android-developer/answer/12564964)
- 填写发布者身份和支持邮箱、提交公开隐私政策网址、审核服务器及账号、前台服务和 VPN 演示视频、发布国家与地区、内容分级、目标受众及广告申报。按[商店资料草稿](store-listing.md)准备实际截图与宣传图。 [上架资料和内容申报](https://support.google.com/googleplay/android-developer/answer/9859455)
