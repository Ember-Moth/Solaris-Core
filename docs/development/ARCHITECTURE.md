# Solaris Core 架构与模块契约

状态：当前开发规范；实现进度见 [开发计划](DEVELOPMENT_PLAN.md)。

## 1. 项目定位

Solaris Core 是全新开发的可嵌入 C 代理内核库，公开配置兼容 mihomo YAML，宿主集成能力参考 libclash。交付库、头文件、薄平台绑定、测试宿主与可复现构建。

自有运行时、配置编译、路由、DNS 和协议代码使用 C，发布数据面不依赖 Go runtime。已有 BoringSSL 依赖包含 C++；本项目不要求所有第三方依赖重新用纯 C 实现。

现有代码是可复用的实现素材。新目录、SDK、模块契约、配置模型和产物独立定义；不承担原 schema、ABI、结构体布局、函数表和宿主调用方式的兼容义务。HTTP 控制器、Web 面板、独立守护进程不属于当前交付目标。

## 2. Solaris 命名

| 对象 | 约定 |
| --- | --- |
| 自有函数 | `solaris_engine_create`、`solaris_config_compile_yaml` 等 `solaris_*` |
| 自有类型 | `solaris_engine_t`、`solaris_stream_t` 等 `solaris_*_t` |
| 宏、枚举常量和 guard | `SOLARIS_OK`、`SOLARIS_EAGAIN`、`SOLARIS_ENGINE_H` |
| 公开头文件 | `include/solaris/`，例如 `<solaris/engine.h>` |
| 构建标识 | `solaris_core`、`SOLARIS_ENABLE_TUN`；消费目标 `Solaris::core` |
| 原生库 | `libsolaris.so`、`libsolaris.a`、`solaris.dll`、`Solaris.xcframework` |
| 公共组件 | `solaris_tls_*` 等中立名称；协议名只用于对应 adapter/codec |

自有目录、include 路径、符号、配置标识、日志引擎标识、导出表、构建脚本、示例和测试统一清理。新工程不保留 `aproxy` 别名、兼容头文件、deprecated wrapper、旧 schema 转换器或 ABI 桥接。

第三方命名、协议标准名称和来源记录按原有规范保留；历史归档中出现旧名称不代表新接口接受它。

## 3. 分层

```mermaid
flowchart TD
    Host[宿主与平台薄绑定] --> API[Solaris C SDK]
    API --> Config[mihomo YAML 编译器]
    Config --> Registry[静态模块注册与配置工厂]
    Registry --> Snapshot[不可变配置快照]
    API --> Control[模式 / 策略组 / Provider / 观测]
    Snapshot --> Control
    Snapshot --> Workers[多 I/O worker 运行时]
    Control --> Workers
    Inbound[入站] --> Flow[Flow dispatcher / UDP association]
    Flow --> Router[Router / DNS]
    Router --> Outbound[Outbound：协议节点或策略组]
    Outbound --> Services[Dialer / Transport / Session]
    Workers --> Flow
    Services --> Platform[Socket / TUN backend / 宿主回调]
```

配置只在准备阶段使用 YAML/通用节点视图。转发热路径访问编译后的结构体、索引和句柄，不查询 YAML/JSON 树。

依赖规则：

- 公开 SDK 不暴露具体协议配置、libuv、BoringSSL 或 lwIP 类型。
- engine、router、flow relay、宿主 SDK 只依赖通用契约，不 include adapter 私有头文件。
- adapter 使用注入的服务和声明的共享 codec/transport；服务不反向依赖某个 adapter。
- 模块配置编译不创建 socket；实例构造不隐式联网，激活和懒连接由任务作用域管理。
- 网络 socket 的创建、protect、接口绑定与取消由统一服务执行，协议不能绕开平台策略。
- 具体平台 API 归 platform/backend，协议代码不直接调用 JNI、Network Extension、Wintun 或 UI。

## 4. 模块接口

| 契约 | 职责 |
| --- | --- |
| `stream` | 有序字节流、读暂停/恢复、写入、背压、半关闭、关闭屏障 |
| `datagram` | 完整消息与地址、零长度报文、多目的能力、有效长度限制、可选批量发送 |
| `outbound` | 查询有效能力，异步打开 stream/datagram，关闭实例 |
| `inbound` | 管理入口，向 dispatcher 交付连接/报文与 metadata |
| `dialer` | 物理网络或经其他 outbound 拨号，统一 DNS、protect、网络绑定和 deadline |
| `transport` | 提供模块允许的 TCP/TLS/WS/gRPC/XHTTP 等载体 |
| `session` | 管理多个子流共享的连接、keepalive、故障传播和退休 |
| `module descriptor` | 名称/别名、配置编译与释放、实例工厂、依赖与能力声明 |

接口采用 opaque state、C 结构体和 const vtable 组合。规则、DNS upstream、provider 使用各自的窄接口，不加入一个覆盖所有业务的巨型 vtable。

内部接口轮廓如下，类型细节由 M0/M1 的实现任务确定；它不是已发布头文件：

```c
typedef struct solaris_outbound_ops {
    int (*capabilities)(void *state, const solaris_flow_meta_t *flow,
                        solaris_outbound_caps_t *out);
    int (*open_stream)(void *state, solaris_open_request_t *request);
    int (*open_datagram)(void *state, solaris_open_request_t *request);
    void (*begin_close)(void *state);
    void (*destroy)(void *state);
} solaris_outbound_ops_t;

typedef struct solaris_outbound_module {
    const char *type_name;
    int (*compile_config)(const solaris_config_view_t *input,
                          solaris_config_compile_context_t *context,
                          solaris_module_config_t **out);
    void (*free_config)(solaris_module_config_t *config);
    int (*create)(const solaris_module_config_t *config,
                  const solaris_module_services_t *services,
                  solaris_outbound_t **out);
} solaris_outbound_module_t;
```

open request 携带只读 metadata、目标、固定的 dial plan、deadline、取消令牌、owner 和一次完成出口。UDP 额外携带 association 上下文，后续目的报文不重新打开整个协议实例。

services 注入 executor、timer、allocator/budget、resolver、dialer、transport factory 与观测设施，不把整个 engine 指针暴露给模块。

## 5. 注册、配置与能力

模块清单是源码、依赖、构建开关与 descriptor 的唯一枚举来源。显式静态注册、显式引用 descriptor，避免静态库裁剪丢失只靠 constructor 自注册的模块。初始化时检查重名、别名冲突和依赖缺失，然后冻结 registry。

配置编译器执行 `lookup → compile_config → resolve dependencies → create`。公共字段由共享 helper 处理，协议模块拥有其私有不可变配置；跨模块引用解析为有代际生命周期的句柄，不在热路径查全局字符串表。

有效能力取实现、实例配置、所选成员和底层服务的交集，至少包含 TCP、UDP、域名目标、多目的数据报、本地映射复用范围、半关闭、批量发送和长度限制。查询无网络副作用，健康状态独立报告。

模块与库一起编译。内部 vtable 不构成动态插件 ABI；普通新增协议不增加宿主 API 函数或协议 enum，也不引入历史版本协商。

## 6. 需要保持的边界

- 策略组实现 outbound 数据面接口，另提供 group control 接口。选中节点、握手状态与健康状态分别表达。
- UDP 封装归 outbound：UoT/XUDP 使用共享 codec，TUN/SOCKS5 只依赖 datagram/association。
- TLS、WS、gRPC、XHTTP 可复用，组合必须由能力与配置声明允许；QUIC 使用适合 UDP/session 的后端，不强制经过 TCP 流水线。
- Vision 等特殊 raw 切换通过窄能力接口表达，并明确顺序；禁止强转其他模块的 `native()` 私有对象。
- 统计、测速、连接关闭和追踪通过通用包装层适用于所有 adapter，业务字节与传输字节在各自边界只计一次。
- 自动重试不得重放已交付给业务或不可重放的应用数据。

## 7. 目录与对象生命周期

```text
include/solaris/       公开 C SDK
src/api/              SDK facade 与宿主命令入口
src/core/             registry、快照与实例编排
src/contracts/        内部模块接口
src/runtime/          worker、mailbox、timer、取消、预算与退休
src/config/           YAML、公共配置、引用图与诊断
src/flow/             metadata、TCP relay、连接追踪
src/flow/udp/         association、mapping、reply endpoint
src/router/           规则解释器与索引
src/dns/              resolver、cache、Fake-IP 与上游
src/provider/         Provider 调度与资源快照
src/adapters/         outbound、inbound、policy 模块
src/transport/        通用载体与 session backend
src/codec/            地址、framing 与协议 codec
src/platform/         平台能力与 TUN backend
modules/              模块与构建清单
tests/                契约、配置、互通、故障与平台测试
```

配置属于 snapshot，模块实例属于 worker/runtime generation，session 属于模块实例，flow/association 持有本次选定的引用。关闭先停止新任务并排空异步完成，引用归零后才 destroy；配置提交不释放仍被旧连接使用的对象。

并行与 I/O 所有权详见 [运行时](RUNTIME.md)，UDP 语义详见 [UDP/NAT](UDP_NAT.md)，宿主边界详见 [配置与 SDK](CONFIGURATION_AND_SDK.md)。

## 8. 框架成立的标准

基础 adapter 就绪后，再增加 SOCKS5 outbound；允许改动协议模块、注册/构建清单、测试和文档，engine/router/TUN/公共 SDK 不增加协议逻辑。新节点应自动参与策略选择、测速、统计、连接关闭和统一生命周期测试。

全新 L3、内核卸载等语义确实超出现有契约时，可评审并扩展窄接口，同时补公共测试；不通过通用模块中的协议特判绕过边界。

参考 mihomo 的 [adapter 契约](https://github.com/Herta-Network/mihomo/blob/9f121787bb563fe655d2789cbf6dbcc7ae19a0c9/constant/adapters.go) 与 [公共 adapter 实现](https://github.com/Herta-Network/mihomo/blob/9f121787bb563fe655d2789cbf6dbcc7ae19a0c9/adapter/outbound/base.go)。调查过程见 [历史归档](../archive/2026-11-03/FRAMEWORK_ARCHITECTURE.md)。
