# Solaris Core

Solaris Core 的新开发目标是一个 **兼容 mihomo YAML、可嵌入、可扩展的 C 代理内核库**，宿主集成方式参考 libclash。

当前源码提供 M0 的新工程骨架和基础 C SDK：异步启停、操作事件、状态快照、完成屏障与安全销毁。旧框架已从源码树移除，保留在 Git 历史中供后续按模块复用。当前只有一个控制 worker，尚未实现 YAML、代理协议或 TUN 数据面。

## 构建基础 SDK

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug --parallel
ctest --test-dir build --build-config Debug --output-on-failure
cmake --install build --config Debug --prefix "$PWD/build/install"
```

需要 CMake 3.24+ 和 C11 编译器，测试还需要 Python 3.9+ 与 C++11 编译器。默认共享库，静态构建添加 `-DBUILD_SHARED_LIBS=OFF`。首次配置下载并校验固定的 libuv 1.53.0。

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
