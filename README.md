# Solaris Core

Solaris Core 的新开发目标是一个 **兼容 mihomo YAML、可嵌入、可扩展的 C 代理内核库**，宿主集成方式参考 libclash。

M1 的实现与本机功能验收已完成：engine 支持多个 I/O worker，内部已实现模块 registry/配置工厂、统一 stream/datagram、资源 scope、UDP association、Direct/Block、中立 TLS、VLESS TCP/XUDP、VLESS encryption/Vision，SS AEAD/2022 TCP/native UDP/UoT v2，以及 AnyTLS v1/v2/session/UoT 路径。内部 select/固定 plan、连接追踪、逻辑/物理流量和 HTTP(S) 单次测速也已接入。SOCKS5 TCP/UDP 扩展试验也已完成；远端 CI 和后续平台/性能验收另行进行，范围及已知限制见 [开发计划](docs/development/DEVELOPMENT_PLAN.md)。HTTP/SOCKS5/mixed 内部入站已实现，支持认证、TCP/UDP 和多监听器，见 [代理入站接入](docs/development/PROXY_INBOUND.md)。公开 SDK 提供启停、事件、状态快照和完成/销毁屏障；YAML、DNAT/Fake-IP 尚未接入。TUN 内部入站已接通 lwIP/system TCP 栈与 UDP association，提供宿主 packet I/O、POSIX FD、utun/Linux TUN 和 Wintun 设备层；接入顺序与限制见 [TUN 用法](docs/development/TUN.md)，尚无真实系统 VPN/驱动验证。旧框架保留在 Git 历史中供后续按模块复用。

## 构建基础 SDK

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug --parallel
ctest --test-dir build --build-config Debug --output-on-failure
cmake --install build --config Debug --prefix "$PWD/build/install"
```

需要 CMake 3.24+、C11/C++17 编译器和 Go（BoringSSL 前缀审计及独立测试对端的构建工具；发布数据面没有 Go runtime）。启用 BoringSSL 需要宿主 Python 3.9+ 和 Git 核验及应用补丁；测试还需要 OpenSSL 命令行用于临时证书。默认共享库，静态构建添加 `-DBUILD_SHARED_LIBS=OFF`。首次配置下载并校验固定的 libuv 、lwIP 2.2.1 与 BoringSSL 0.20261020.0，并严格应用项目内五个补丁；协议测试构建 lock 中固定版本的 sing-box、Xray 和 TLS 认证对端（需要 Go 1.27+，支持 Go 自动工具链下载），只启动 loopback 代理对端。

内置出站可用 `-DSOLARIS_ENABLE_DIRECT=OFF`、`-DSOLARIS_ENABLE_BLOCK=OFF`、`-DSOLARIS_ENABLE_VLESS=OFF`、`-DSOLARIS_ENABLE_SHADOWSOCKS=OFF`、`-DSOLARIS_ENABLE_ANYTLS=OFF`、`-DSOLARIS_ENABLE_SOCKS5=OFF` 分别裁剪。关闭 VLESS、Shadowsocks 与 AnyTLS 后可同时关闭 `SOLARIS_ENABLE_PROXY_TRANSPORT` 与 `SOLARIS_ENABLE_TLS`，移除 BoringSSL 依赖；SOCKS5 可独立保留。已有固定版本对端可通过 `SOLARIS_REFERENCE_PEER`（sing-box）和 `SOLARIS_XRAY_REFERENCE_PEER`（Xray）指定；配置和注册行为见 [M1 实现说明](docs/development/M1_DATA_PATH.md)。

HTTP/SOCKS5/mixed 入站可用 `SOLARIS_ENABLE_PROXY_INBOUND=OFF` 整体裁剪，同时移除 llhttp 依赖。

TUN 可用 `SOLARIS_ENABLE_TUN=OFF` 整体裁剪，或分别关闭 `SOLARIS_ENABLE_TUN_LWIP` / `SOLARIS_ENABLE_TUN_SYSTEM`；关闭 lwIP 后不下载或链接该依赖。

安装后使用 `find_package(Solaris CONFIG REQUIRED)` 与 `Solaris::core`。可调用接口和回调/销毁约定见 [当前 SDK 用法](docs/development/SDK.md)；构建与依赖取舍见 [M0 决策](docs/development/M0_DECISIONS.md)。

## 开发入口

从 [开发文档索引](docs/README.md) 开始，实施顺序和完成状态以 [开发计划](docs/development/DEVELOPMENT_PLAN.md) 为准。

| 文档 | 内容 |
| --- | --- |
| [架构与模块契约](docs/development/ARCHITECTURE.md) | 项目边界、Solaris 命名、模块接口、依赖和扩展规则 |
| [配置与宿主 SDK](docs/development/CONFIGURATION_AND_SDK.md) | mihomo 配置兼容、C API、平台职责和配置更新 |
| [运行时与多核](docs/development/RUNTIME.md) | 多 libuv loop、对象归属、任务池、消息与 TUN 栈边界 |
| [UDP 与 NAT](docs/development/UDP_NAT.md) | association、目的映射、通道复用、回复恢复与生命周期 |
| [测试与验收](docs/development/TESTING.md) | 契约、差分、互通、平台与性能证据 |
| [开发计划](docs/development/DEVELOPMENT_PLAN.md) | M0–M6、任务编号、依赖、交付物、验收和当前进度 |
| [当前 SDK](docs/development/SDK.md) | 已实现的 C API、构建、消费和生命周期契约 |
| [兼容矩阵](docs/development/COMPATIBILITY.md) | 当前支持、未实现和未验证的能力 |
| [TLS 后端](docs/development/TLS_BACKEND.md) | BoringSSL 固定基线、补丁与 REALITY/ShadowTLS/Restls/JLS 认证边界 |
| [M1 实现](docs/development/M1_DATA_PATH.md) | 模块工厂、UDP association、多 worker 和统一 I/O 的实际行为、验证与限制 |

## 已确定的方向

- 按全新项目开发，选择性复用原有算法和协议实现，不承担原 schema、ABI 或接口兼容义务。
- 自有函数/类型使用 `solaris_*`，宏使用 `SOLARIS_*`，公开头文件放在 `include/solaris/`。
- 新协议以模块方式加入；engine、router、TUN、策略组及宿主 SDK 不增加协议特判。
- 宿主通过 C API 控制库，负责系统 VPN 权限、TUN 和平台能力；不以 HTTP 控制器或 Web 面板作为交付目标。
- 一个 engine 管理多个 I/O worker，每个连接、UDP association 和共享 session 固定 owner。
- UDP 使用独立的 association、目的映射和回复端点模型，兼容行为与实现限制都有测试依据。

## 历史与来源

原 README、嵌入说明和讨论草案已移入 [历史归档](docs/archive/README.md)，其中包含原实现的检查记录和本地 UDP 探针。归档不作为新的开发规范。

第三方来源声明继续保留在 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 和相应第三方目录中。
