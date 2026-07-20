# Solaris Core

Solaris Core 是 Solaris 的可嵌入 C 数据面库，覆盖 Android、Apple 和 Windows；Apple 同时覆盖
iOS 与 macOS。目录中不再增加 `aproxy-core` 中间层：

```text
Solaris-Core/
├── CMakeLists.txt
├── docs/
├── examples/
├── include/
├── src/
├── scripts/
└── third_party/
```

源码基于 aproxy-core 提交 `e680b74`，已收敛为 Solaris 所需的 engine、协议、
依赖构建和许可证文件。上游测试、benchmark、CLI、示例与包发布辅助文件不进入本项目。

## C SDK

公开 C ABI 入口为 `include/solaris/core.h` 和 `include/aproxy/engine.h`。安装后的 CMake
包名为 `Solaris`，导入目标固定为 `Solaris::core`：

```cmake
find_package(Solaris CONFIG REQUIRED)
target_link_libraries(your_host PRIVATE Solaris::core)
```

`Solaris::core` 只提供数据面库。宿主仍必须实现平台 TUN、packet callback、socket protect、
配置转换、状态持久化和系统 VPN 生命周期。嵌入规则见 `docs/EMBEDDING.md`。

## xmake 构建

`xmake.lua` 是独立 SDK 的新构建入口。xmake 会通过本地 package 描述下载 pinned 依赖：

- patched BoringSSL：`922c15f36cc75db5af33c46f9ea8934553fb808e`
- libuv：`8fb9cb919489a48880680a56efecff6a7dfb4504`
- PCRE2：`b2bd4254b379b9d7dc9a3dda060a7e27009ccdff`
- nghttp2：`526ff38e0249acbcc4d0e8958c12cdeae9960cfe`
- llhttp：`610a87d755f6bae466cd871c2ba97574ccac5483`
- lwIP：`77dcd25a72509eb83f72b033d219b1d40cd8eb95`

常用入口：

```sh
xmake f -m release
xmake
xmake install -o build/install
```

Android 示例：

```sh
xmake f -p android -a arm64-v8a --ndk="$ANDROID_NDK_HOME" -m release
xmake
```

iOS 示例：

```sh
xmake f -p iphoneos -a arm64 -m release
xmake
```

CMake 文件暂时保留为迁移期对照；删除前需要确认 xmake 产物、ABI、头文件安装和四个平台构建
行为完全等价。

## 配置

公开输入是一行一条的分享链接。Android、Apple 和 Windows 在各自 Perry FFI 内调用同一份
`native/vpn-config` Rust 解析器，将链接编译为平台私有 `tunnel` 与内部 `kernel` 对象，再映射
到 aproxy schema root。C core 不解析分享链接。以下字段由平台适配层管理，业务代码不得直接
构造：

- 当前 schema version 为 `2`；engine 不接受仍把 UDP transport 放在 TUN 的 version 1 配置。
- `revision`：配置修订号，默认 `1`。
- `tun`：设置 sniff、队列和 idle timeout 等 TUN engine 参数；UDP transport 由 outbound 决定。
- `inbounds`：始终被覆盖为唯一的 TUN inbound。
- TUN 类型、地址、前缀和 MTU 始终来自平台 `tunnel` 配置。

节点与多路由方案的内部形状：

```json
{
  "tunnel": {
    "sessionName": "Solaris",
    "mtu": 1400,
    "address": "10.8.0.2",
    "prefixLength": 24,
    "ipv6Address": "fd00:7357:1::2",
    "ipv6PrefixLength": 64,
    "dnsServers": ["1.1.1.1", "2606:4700:4700::1111"],
    "routes": ["0.0.0.0/0", "::/0"]
  },
  "kernel": {
    "revision": 1,
    "outbounds": [
      {
        "type": "anytls",
        "tag": "node:hk-anytls",
        "server": "vpn.example.com",
        "port": 443,
        "password": "replace-me",
        "uotVersion": 2,
        "security": "tls",
        "sni": "vpn.example.com"
      }
    ],
    "routeProfiles": [
      {
        "id": "cn-direct",
        "default": "proxy",
        "rules": [
          { "type": "geoip", "value": "cn", "outbound": "direct" },
          { "type": "geosite", "value": "cn", "outbound": "direct" }
        ]
      },
      { "id": "global", "default": "proxy", "rules": [] }
    ],
    "selection": {
      "node": "node:hk-anytls",
      "routing": "cn-direct"
    }
  }
}
```

Apple 还会生成 `remoteAddress: "127.0.0.1"`，Windows 还会生成
`adapterName: "Solaris"`；Android 没有这两个平台字段。上述对象是内部边界示例，不是公开
配置文件格式。

TUN schema 不接受 `udpRelayMode`/`uotVersion`。AnyTLS 固定 UoT（默认版本 2），VLESS 固定
XUDP，Direct 固定原生 UDP；Shadowsocks 默认原生 UDP，可用 outbound 的
`"udpTransport": "uot"` 和 `"uotVersion": 1|2` 显式切换。

Solaris 产品配置默认启用 route-only sniff：TCP 从已有 ring spans 原地读取 HTTP/1 Host 与
TLS ClientHello SNI，UDP/443 解密 QUIC v1/draft-29 Initial 并重组有界 CRYPTO 数据。域名只
参与 router 选路，outbound 仍连接原始 IP。默认上限为 TCP/QUIC 16 KiB、TCP 100 ms、QUIC
4 个数据报；无法识别时回退原 IP，不实现 FakeDNS。
router 没有 domain/domainSuffix/geosite 规则时自动跳过 sniff。

`proxy` 不是实际 outbound tag，而是 router 的逻辑槽。`select_node` 在连接目标节点成功后更新
该槽；default 和显式 proxy 规则都会对新 flow 解析到目标节点。`routeProfiles` 在启动时全部
编译，`select_routing` 只切换 active profile。启动不会再调用 `connect_all`，未选节点只保留
轻量配置对象。

示例域名和密码不可直接使用。各平台配置转换器均限制输入大小、嵌套深度和节点
数量；密码、UUID、私钥和 Token 不得写入日志。

## Android

```text
PerryTS -> Rust supervisor -> libcore.so -> lwIP/TUN
                            -> async protect -> JNI -> VpnService.protect()
```

Rust 拥有 Kotlin `detachFd()` 转移的系统 TUN fd，并为 aproxy 创建一个适配器副本。
`get_tun_fd` 返回借用值，aproxy 不关闭该 fd。上游 socket 必须在 `connect()` 前完成
异步 `VpnService.protect()`；停止时先关闭 protect 请求入口并排空已接受请求，再停止和
销毁 engine，最后关闭 TUN fd。

Android 构建产物包含 `libcore.so`、`libc++_shared.so` 和 `libperry_app.so`。三个库的
`PT_LOAD` 段必须至少按 16 KiB 对齐，最终 APK 还会经过 `zipalign -P 16` 检查。

内核单独构建入口：

```sh
ANDROID_NDK_HOME=/path/to/android-ndk \
  scripts/build_android.sh arm64-v8a
```

输出位于 `build-android/install/<abi>/lib/libcore.so`。ABI 可使用
`arm64-v8a`、`armeabi-v7a`、`x86` 或 `x86_64`。

某些 NDK 29 安装中缺失 `llvm-strip` 时使用 `llvm-objcopy --strip-unneeded`；缺失
`llvm-readelf` 时使用 `llvm-readobj --program-headers` 检查 16 KiB `PT_LOAD` 对齐。可通过
`SOLARIS_ANDROID_STRIP_BIN`、`SOLARIS_ANDROID_READELF_BIN` 和
`SOLARIS_ANDROID_READOBJ_BIN` 覆盖工具路径。

## Apple

Apple 的 iOS 与 macOS 复用同一套公开 `NEPacketTunnelFlow` packet callback 数据面和平台
适配器，但分别生成目标系统对应的 XCFramework。

### iOS

iOS 数据面只使用公开的 `NEPacketTunnelFlow`：

```text
packetFlow.readPackets -> submit_tun_packets -> aproxy/lwIP
packetFlow.writePackets <- copied packet batch <- write_tun_packets
```

`core.xcframework` 只链接到 Packet Tunnel Extension。PerryTS 宿主 App 通过系统 IPC
控制 Extension，不持有 engine、数据面指针或 fd。输入包由 aproxy 在 API 返回前复制；
输出包由 Objective-C++ 桥接层复制为 `Data` 后交回系统。

在带完整 Xcode 的 macOS 上运行 `scripts/build_ios.sh`，会生成包含
`iphoneos/arm64` 与 `iphonesimulator/arm64+x86_64` 的 `build-ios/core.xcframework`。

### macOS

macOS 与 iOS 复用公开的 `NEPacketTunnelFlow` packet callback 数据面，但生成单独的
`build-macos/core.xcframework`，并只链接到 macOS Packet Tunnel app extension：

```sh
scripts/build_macos.sh
```

宿主 App 仍只通过 `NETunnelProviderManager` 控制 Extension；core 不链接到宿主进程。

## Windows

Windows 输出固定命名为 `core.dll`，由 Rust supervisor 动态加载；系统 TUN 使用官方
`wintun.dll` packet ring，core 只看到 packet callback：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_windows.ps1
```

`wintun.dll` 由使用者从官方发布包提供，不属于内核源码，也不会被构建脚本下载。

## BLAKE3 架构优化

- Android `arm64-v8a` 与 Apple arm64 使用 NEON intrinsic，由 Clang 生成 SIMD 指令。
- Android `armeabi-v7a` 单独以 `-mfpu=neon` 编译优化后端，并通过 `HWCAP_NEON`
  在运行时回退到 portable 实现。
- Android `x86` 使用官方 SSE2、SSE4.1、AVX2、AVX-512 intrinsic 和 CPUID 分派。
- Android `x86_64`、iOS Intel 模拟器与 Intel macOS 使用官方 x86-64 SIMD 汇编和 CPUID
  分派。
- Windows x86_64 使用官方 SSE2、SSE4.1、AVX2、AVX-512 intrinsic 和运行时 CPUID 分派。

## UDP 批处理与内存边界

Direct outbound 和 SOCKS5 UDP associate 创建 socket 时请求 libuv 的
`UV_UDP_RECVMMSG`。当前固定的 libuv 1.50 在 Android/Linux 使用 `recvmmsg()`，在 Apple
使用 `recvmsg_x()`；Windows 不支持该接收模式，自动回退到普通 IOCP UDP 接收。每批最多
接收 2 个报文，批量缓冲为 128 KiB。这个缓冲不是按 UDP flow 常驻分配，而是由同一个
Direct outbound 或 SOCKS5 inbound 共享，最多缓存 1 块；最后一个对应 flow/connection
关闭后立即清空。全局动态内存预算拒绝 128 KiB 预留时，接收会回退到可复用的 64 KiB
单报文缓冲，不因优化突破 `memory.dynamicLimitBytes`。

TUN native UDP relay 利用已有输入批次的借用生命周期合并同一 flow 的连续报文，只保存
描述符，不额外复制 payload，也不等待定时器凑批；批次外的单个低延迟报文仍直接发送。
fd 型 TUN 每轮用一块共享的 `16 * MTU` 缓冲先读最多 16 个包；内存预算拒绝该块时自动
退回一块 `MTU` 大小的单包缓冲。packet callback 型 TUN 直接借用 engine 已经接收的
ingress ring，二者都在释放或复用输入内存前完成发送。每批最多 16 个报文；Direct
outbound 通过 `uv_udp_try_send2()` 在 Android/Linux 映射到
`sendmmsg()`、在 Apple 映射到 `sendmsg_x()`，Windows 由 libuv 逐报文回退。Shadowsocks
先逐报文完成加密，再把密文数组交给同一个批量接口；VLESS XUDP、AnyTLS UoT 等流式 UDP
保持原有 stream framing，不错误套用 datagram syscall。

Direct UDP 在 `sendmmsg()` 遇到背压后使用独立的 16 KiB fallback write pool，不再与 TCP
write pool 共享高水位。每批最多保留 16 块；最后一个异步 UDP send 回调完成时立即 trim
buffer 与 request pool。trim 发生在 in-flight 归零之后，不会提前释放 libuv 仍在借用的
payload。

UDP relay 与 Shadowsocks 的 9 KiB packet pool 空闲块上限均收紧为 16，恰好覆盖最大发送
批次；最后一个对应 session/packet flow 退出后会主动清空缓存。这样不会为了批处理把旧的
64/128 块高水位长期保留在 VPN 进程中。

engine 的 `get_stats()` 提供以下 TUN 数据面计数，便于确认真实业务流量是否进入批量发送和
sniff 路径；三端私有平台包可以读取同一份快照，节点级业务 API 不直接暴露这些内核计数：

- `tunUdpNativePacketsOut`
- `tunUdpNativePayloadBytesOut`
- `tunUdpNativeSendBatches`
- `tunUdpNativeSendBatchPackets`
- `tunSniffAttempts`
- `tunSniffMatches`
- `tunSniffHttpMatches`
- `tunSniffTlsMatches`
- `tunSniffQuicMatches`
- `tunSniffFallbacks`
- `tunSniffTimeouts`

其中 `tunUdpNativeSendBatches` 只统计由批量实现一次接受两个及以上报文的调用；它证明批量
接口命中，不单独证明 OS 一定完成了批量 syscall，因为拥塞回退和 Windows 实现仍可能逐包
发送。代码不把 syscall 减少量直接写成吞吐收益；目标设备仍需用相同流量、相同网络和相同
CPU/电源条件做 A/B 测量，并同时记录吞吐、p50/p95 延迟、CPU、
`processMemoryBytes`、`dynamicMemoryPeakBytes`、上述批量计数和系统调用跟踪。

## Geo 数据库内存策略

GeoIP 与 Geosite 在配置阶段使用只读 mmap；建立索引的前向扫描使用顺序访问提示，索引
完成后恢复系统默认的平衡预读策略，避免按 code 编译条目时发生不必要的重复缺页。一次
配置加载中，同一路径只扫描和建立一次索引，多个路由规则复用该索引。规则编译完成后
会立即解除映射并释放索引，转发阶段只查询紧凑的 CIDR、域名表、关键字自动机和正则
结构，不依赖数据库文件。同一路径、同一 GeoIP code 或 Geosite selector 被多条规则引用
时，规则还会共享同一份只读编译结果；每条规则仍独立保留原有顺序和 outbound，不会因
复用改变优先级。该复用在数据库索引主动释放后仍有效。

这里保留 mmap 而不改成 `pread()`：数据库只在配置阶段做顺序扫描，mmap 让页缓存直接作为
只读输入，避免 `pread()` 的每批系统调用、用户缓冲区及一次额外复制。规则编译后立即
`munmap`，稳定转发期只保留紧凑索引，因此改成 `pread()` 通常不会降低稳定 RSS，反而会
增加配置阶段 CPU 和临时 buffer。真正的内存收益来自尽早解除映射、共享编译结果和压紧
运行期结构。

高层 API 通过独立的 `prepareGeoData()` 接收下载声明并发布 current；含 Geo 规则的
`startVpn()` 只生成内部 `{ geoData: { managed: true } }` 引用。Android、
Apple 和 Windows 平台层在校验并原子发布完整版本后，才把沙箱内的绝对路径注入内核
对应 `routeProfiles[].geoipPath`/`routeProfiles[].geositePath`。内核本身不下载文件，也不
持有 URL、凭据或平台容器规则。

Geosite 每类紧凑表生成后立即释放对应原始字符串，正则源码也会随编译进度释放；关键字
自动机使用连续节点数组，并把边拆成紧凑的 1 字节 value 与 4 字节 next 数组，消除普通
C 结构体的对齐空洞；节点出边计数压缩为 16 位。GeoIP 的前缀 offset 使用 32 位值，并将
排序去重后的 IPv4、IPv6 builder 原地压紧后直接转移为运行期数组，不再同时分配一份完整
结果。数据库索引扫描结束后收缩增长余量；路由完成时也收缩规则、Geo rule index 和 CIDR
trie 的未用容量。数据库映射和其余构建中间结构都不计入稳定运行期内存。

转发热路径中，每个 FQDN 只在 router 层执行一次 ASCII 小写转换，所有 Geosite 规则共享
同一只读栈缓冲；只有带尾点的非常规形式需要额外终止处理。纯 Geosite 配置不会因此运行
空的普通域名索引。

DNS 返回 A/AAAA 后，router 不再按“全部规则 × 全部地址”倒序扫描。域名、每个 IPv4/IPv6
地址分别通过现有 domain/CIDR/Geo 索引得到原始 `rule_index + 1`，最终取最大值，因此仍严格
保持后添加规则优先。处理后续地址时会把当前最大序号作为下界，序号不可能更高的规则不会
再次匹配；该优化不增加索引或稳定期内存。

阶段性基准、测量方法和适用边界见 [项目状态](../docs/PROJECT_STATUS.md)。

## 第三方源码

固定 commit 在本地构建目录不存在时，首次平台构建会拉取 BoringSSL、libuv、lwIP、PCRE2、
nghttp2 和 llhttp，并应用 `third_party/boringssl-reality.patch`。后续 Android 构建复用已经
固定的 BoringSSL 对象，并使用 `FETCHCONTENT_UPDATES_DISCONNECTED` 避免依赖更新访问；删除构建
目录后重新构建仍需要网络。工作目录位于项目忽略的构建目录。许可证见 `LICENSES/` 和
`THIRD_PARTY_NOTICES.md`。
