> 历史归档（2026-11-03）：原路径 `docs/EMBEDDING.md`。本文件仅供追溯；当前开发依据见 [开发文档入口](../../README.md)。正文保留归档时状态，链接已按归档位置调整。

# 嵌入 Solaris Core

> 本文描述尚待替换的原实现，供查阅其当前调用方式。全新 Solaris 工程的接口与配置模型以 [总体设计](MIHOMO_LIBRARY_DESIGN.md) 和 [框架架构](FRAMEWORK_ARCHITECTURE.md) 为准；下文的版本、函数表和私有配置格式不构成新项目的兼容要求。

Solaris Core 是一个 C ABI 数据面库。它不创建系统 VPN、不申请权限、不解析分享链接，也不下载
Geo 数据库；这些职责属于宿主程序。

## CMake

安装后的包名是 `Solaris`，目标名是 `Solaris::core`：

```cmake
find_package(Solaris CONFIG REQUIRED)
target_link_libraries(your_host PRIVATE Solaris::core)
```

源码树内也提供同名 alias，便于作为子目录集成：

```cmake
add_subdirectory(path/to/Solaris-Core)
target_link_libraries(your_host PRIVATE Solaris::core)
```

## ABI 入口

推荐包含产品级头文件：

```c
#include <solaris/core.h>
```

底层 ABI 在 `aproxy/engine.h` 中定义。唯一稳定符号是
`aproxy_engine_get_api()`；`solaris_core_get_api()` 是薄包装。宿主应检查：

- `SOLARIS_CORE_ENGINE_ABI_VERSION`
- `api->abi_version`
- `api->struct_size`

所有 `aproxy_string_view_t`、`aproxy_bytes_view_t` 和 `aproxy_value_t` 指针默认都是借用。
事件、状态和统计回调中的指针只在回调返回前有效。

## 宿主回调

`aproxy_engine_host_v2_t` 由宿主提供，核心字段如下：

- `emit_event`：接收状态和 operation 完成事件。
- `protect_socket`：同步 pre-connect socket 绑定/保护，适合 Windows 或 Apple。
- `submit_socket_protect` / `complete_socket_protect`：异步 socket protect，适合 Android
  `VpnService.protect()`。
- `get_tun_fd`：返回宿主拥有的借用 TUN fd，适合 Android fd 型 TUN。
- `write_tun_packets`：接收 core 输出包，适合 Apple `NEPacketTunnelFlow` 或 Windows Wintun
  packet ring。

fd 所有权必须由宿主持有。`get_tun_fd` 返回的 fd 不会被 core 关闭；宿主必须等
`stop()` operation 完成并调用 `destroy()` 后再关闭 fd。

## 配置

Core 接收 `aproxy_engine_config_v2_t`，schema 固定为：

- `schema_id`: `aproxy.proxy-config`
- `schema_version`: `2`

Core 不解析 JSON 或分享链接。宿主需要把自己的配置转换成 `aproxy_value_t` 对象树，并在调用
`validate_config()`、`start()` 或 `reload()` 后保持内存有效，直到函数返回。Core 会在排队前
深拷贝配置树。

VPN 产品通常应构造唯一 TUN inbound：

- `inbounds`: 只允许一个 inbound。
- `type`: `tun`。
- TUN 地址、前缀、MTU 来自平台 tunnel 配置。
- UDP transport 配在 outbound，不配置在 TUN。

## 生命周期

基本顺序：

1. 调用 `solaris_core_get_api()`。
2. 填充 `aproxy_engine_host_v2_t`。
3. 调用 `api->create()`。
4. 调用 `api->validate_config()` 或 `api->start()`，等待对应 operation event。
5. 运行中可调用 `api->reload()`、`api->select_node()`、`api->select_routing()`。
6. 停止时先停止宿主 packet/fd admission，再调用 `api->stop()` 并等待 operation event。
7. 调用 `api->destroy()`。
8. 释放宿主 TUN、packet ring、路由、DNS 和平台状态。

`destroy()` 会阻塞直到 core 拥有的线程和回调全部退出。

## 平台边界

Android：

- 宿主拥有系统 TUN fd。
- Core 只借用 fd。
- socket 必须在 `connect()` 前通过异步 `VpnService.protect()` 完成。

Apple：

- Core 只能链接到 Packet Tunnel Extension。
- 使用 `submit_tun_packets()` 输入包，使用 `write_tun_packets` 输出包。
- 不扫描或传递私有 utun fd。

Windows：

- Wintun packet ring 属于宿主。
- Core 通过 packet callback 收发包。
- 新 socket 在 `connect()` 前绑定物理接口。

## 示例

`examples/minimal_host.c` 演示了如何获取 API、创建 engine、读取 capabilities 并销毁 engine。
它不启动 VPN，因为真实启动需要平台 TUN 和完整 schema v2 配置。

## xmake

源码树可以直接作为 xmake 项目使用：

```sh
xmake f -m release
xmake
xmake install -o build/install
```

构建目标名为 `core`，输出 basename 为 `core`。依赖由 `xmake/packages.lua` 固定到 Solaris
使用的提交；BoringSSL 会在 package install 阶段应用 `third_party/boringssl-reality.patch`。

迁移期仍保留 CMake package config，以便下游继续使用 `Solaris::core`。如果下游也迁移到
xmake，可以通过源码子项目或安装后的库/头文件接入。
