# SoftEther native core for Android

This source package builds `vpnclient` and `vpncmd` for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`, plus the shared HamCore asset. The programs are PIE executables with `.so` filenames so Android can extract them to the app’s native library directory.

## Pinned inputs

| Component | Revision | Role |
| --- | --- | --- |
| SoftEtherVPN_Stable | `v4.44-9807-rtm`, `ed17437af9719ac66acab30faa29e375d613c35f` | Cedar and Mayaqua objects from the Linux makefile for each word size and the `vpnclient` and `vpncmd` entry points |
| OpenSSL 3.5 LTS | `openssl-3.5.9`, `45e844fa2a14ec92d146bd8f5778ac130b6625fb` | Public headers and static crypto and TLS libraries built per ABI |
| Android NDK | `28.2.13676358` (r28c) | Clang 19 for four Android targets at native API level 28 |
| Build tools | Git, CMake, Ninja, JDK 21, Bash, GNU Make and Perl | Source preparation, native build, and HamCore generation |

The build verifies the OpenSSL release archive SHA-256 before extraction. Each target builds its own headers and archives. [SoftEther source](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/tree/ed17437af9719ac66acab30faa29e375d613c35f) · [OpenSSL release](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9) · [License files](licenses/)

`softether-android.patch` contains changes to upstream sources. `compat/` contains the Android runtime adapter and line console. `tests/` holds native host tests. The Android app separately targets API 36.

## Build and stage

The GitHub Actions workflow builds the core on Ubuntu. It verifies `sourcepack-manifest.json`, checks the pinned SoftEther revision and patch, and builds OpenSSL static libraries for each ABI. Update the sourcepack manifest alongside intentional changes to its inputs. [Build Android APK](https://github.com/M0Sheng/Unofficial-SoftEther-VPN/actions/workflows/pre-release-apk.yml)

The native build stages both programs for each ABI in `app/src/main/jniLibs/`, generates the shared HamCore asset, and records SHA-256 hashes in `native-core-source/out/artifacts.json`. The APK build checks the complete set before packaging. Download the finished APK from the workflow run or Releases. [Releases](https://github.com/M0Sheng/Unofficial-SoftEther-VPN/releases)

## Run on Android

### TAP

The rooted backend runs the Unix adapter over a nonpersistent kernel TAP. The app-owned logical NIC `home` uses `HOMEVPN_MANAGED_TAP` for the validated session-specific `eth` or `usb` name and `HOMEVPN_TAP_TOKEN` for a UUID identifying the creation request. Exclusive creation returns the actual interface name and ifindex in `HOMEVPN_TAP_CREATED`. Android handles addressing and routing after creation. Other logical NICs use upstream `vpn_<name>` names.

`HOMEVPN_DISABLE_IPV6=1` filters IPv6 frames in both directions for `home`, including nested VLAN tags. `HOMEVPN_DISABLE_UDP_ACCELERATION=1` disables UDP acceleration for the managed account. SoftEther NAT-T/RUDP transport fallback is an independent setting. `HOMEVPN_DEFER_STARTUP=1` defers saved-account login until the owner explicitly connects. Automatic mode enables native checking of the verified leaf certificate before `AccountConnect`.

### TUN

TUN runs the same native core under the Android app UID. The logical NIC exchanges Ethernet frames through a Unix sequenced-packet socket. Kotlin manages the Android `VpnService` IP interface. Rust handles the link’s DHCP, ARP, and IPv6 address discovery.

The app provides `HOMEVPN_FRAME_SOCKET`, `HOMEVPN_ROOTLESS_RPC_PORT`, and a separate per-run management secret. The core reports `FRAME_CHILD_PID` and `FRAME_RPC_READY`. Both ends validate process and UID before the app passes a frame-channel descriptor. The CLI targets the selected IPv4 loopback endpoint. The TUN direct transport uses TCP with NAT traversal and explicit RUDP fallback disabled. Optional UDP acceleration has its own setting.

`HOMEVPN_FRAME_MAC`, `HOMEVPN_FRAME_TLS_VERSION`, and `HOMEVPN_FRAME_TLS_CIPHERS` carry app-managed adapter and handshake settings. For GBK standard authentication, the app sends encoded bytes through a private command file using `AccountPasswordSet /TYPE:standard-hex`. The core decodes those bytes before applying the SoftEther standard credential hash.

### Process ownership and underlay

- `vpnclient androidsvc` runs under the foreground owner. A private process-lifetime lock guards the daemon’s runtime directory and checks for an active legacy SoftEther lock before startup. `HOMEVPN_DATA_DIR` supplies the private configuration and scratch directory.
- The app owns the daemon and CLI stdin pipes. EOF triggers self-termination, including a timed self-kill if shutdown stalls. The rooted runner confirms owned children exited before releasing the core directory for reuse.
- `HOMEVPN_UNDERLYING_NETWORK_HANDLE` binds native traffic and DNS to the selected Android network. The app retains the selected network for the session and reconnects on underlay loss according to its connection policy.
- The Android adapter accounts for `=` in APK paths and Bionic’s UTF-8 conversion of terminating NUL bytes. Native credentials and batch commands are passed through private files to keep them out of the process argument list.

## Management interface

The app and CLI use the per-run secret for loopback RPC. TAP can also expose the native client-management port on TCP `9930` when the phone’s remote-management option is enabled and a separate remote password is configured. TUN uses loopback management only.

From the official desktop VPN Client Manager, use the phone’s reachable address in the remote-client entry. The CLI uses a host-only target and prompts for the remote password.

```text
vpncmd PHONE_IP /CLIENT
```

Use the management connection within a trusted LAN or an existing encrypted tunnel. The desktop protocol sends a reusable SHA-0 password equivalent and carries RPC without TLS. The phone persists the remote hash in `remote-management.sha0` with private file permissions, separately from app-local authentication. The remote enable gates control authentication and subsequent requests. Switch off remote management on the phone and restart the session to remove the external listeners.

External listeners require Android’s existing `tcp_fwmark_accept=1` setting. Accepted sockets are bound to the interface owning the local destination address for consistent reply routing. See the Android routing implementation for the existing platform behavior. [Android init setting](https://android.googlesource.com/platform/system/core/+/da870abcf48305312bdea618bb97a4280ab7e444/rootdir/init.rc) · [netd routing rules](https://android.googlesource.com/platform/system/netd/+/refs/heads/main/server/RouteController.cpp)

## Verification scope

The build verifies the staged files and reads back the generated HamCore asset. Optional host tests cover the remote authentication policy, TAP interface policy, and SoftEther SHA-0 vectors. The GitHub Actions workflow also runs the Rust and Android unit tests and Android lint.

See [Functional scope](FUNCTION_MATRIX.md) for the distinction between app-managed features and handlers available through TAP management. See [Root routing notes](../docs/ROOT_ROUTING.md) for Android backend constraints.
