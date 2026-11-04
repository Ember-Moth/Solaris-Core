> 历史归档（2026-11-03）：原路径 `docs/FRAMEWORK_ARCHITECTURE.md`。本文件仅供追溯；当前开发依据见 [开发文档入口](../../README.md)。正文保留归档时状态，链接已按归档位置调整。

# Solaris Core 框架架构与模块扩展契约

状态：全新开发的设计提案，尚未实施。日期：2026-11-03。

本文是 [mihomo 配置兼容库设计](MIHOMO_LIBRARY_DESIGN.md) 的架构约束。配置兼容、作为库使用、宿主负责平台 VPN 能力的目标保持不变。

本项目按全新 Solaris 工程设计。原源码是实现素材，不承担原 schema、ABI、函数签名、对象布局或构建接口的兼容义务。删除 `aproxy` 自有命名及对应兼容包装，新的代码和接口统一采用 `solaris` 命名。

UDP 的 association、映射、路由固定与回复端点按 [UDP / NAT 设计核对](UDP_NAT_DESIGN.md) 细化；该文档也修正了此前将 UDP 子流与独占出站通道等同的假设。

单 owner 是对象级线程约束。一个 engine 管理多个 I/O worker/loop，跨连接并行，具体分派、共享 session 与 lwIP 栈边界见 [运行时与多核并行设计](RUNTIME_CONCURRENCY_DESIGN.md)。

## 1. 可验收的扩展目标

新增一种能映射为 TCP 字节流和/或 UDP 数据报的代理协议，应只需要：

1. 增加一个 adapter 模块，提供配置解码/校验、工厂、TCP/UDP 行为和生命周期实现。
2. 在模块清单中声明名称、别名、依赖、可选构建项和注册 descriptor。
3. 增加协议测试样本和独立对端互通用例，运行公共 adapter 契约测试。

engine、router、TUN、入站 relay、策略组、宿主 ABI 不随协议名称增长分支。节点枚举、通用测速、统计、日志和连接关闭通过统一接口自动适用于新模块。

框架成立的证明：按新契约实现基础协议后，再增加 SOCKS5 outbound，完成 TCP/UDP 转发、组内选择、健康检查、统计和停止清理。审查实际改动范围，确认没有触及上述通用模块的协议逻辑。

引入全新的数据语义（例如 L3 隧道、特殊内核卸载）可能需要新增窄接口。这应作为独立的框架变更评审，不能伪装成普通 stream，也不能以支持一个协议为由扩大通用模块对其私有结构的依赖。

## 2. 当前结构需要改变的地方

| 现状 | 扩展时的影响 | 目标边界 |
| --- | --- | --- |
| `engine.c` 包含各协议头，逐类型校验、填 config、创建实例 | 每加协议都修改编排器；解析入口和实现容易脱节 | engine 编排通用生命周期；模块拥有自己的 config codec/factory |
| `library.c` / `library.h` 提供 `add_anytls/add_vless/add_shadowsocks` | 库构造层随协议扩张 | 直接采用 `registry → factory → outbound`，删除原逐协议构造入口 |
| TUN UDP relay 与 SOCKS5 inbound 实现 UoT | 入站了解出站 wire format；策略组难以混用协议 | adapter 输出统一 datagram；封装放在 adapter/shared codec |
| 共用 TLS 操作沿用 `anytls_tls_client_*` | 协议与通用传输边界混淆，VLESS/XHTTP 依赖其具体能力 | 中立的 TLS transport/service，特殊 raw 切换用明确 capability |
| stream vtable 只有 write/close/free 等基础操作 | 背压、读暂停、半关闭和关闭屏障不能作为统一契约复用 | 完整 I/O 契约及可复用的双向 relay |
| capability 与类型名单在 engine 中硬编码 | 配置、构建和查询可能给出不同支持范围 | descriptor + 实例配置 + 下层服务能力共同产生有效能力 |

vtable、缓冲池、codec 和协议算法可以选择性复用，接受新的所有权、依赖和命名契约后再进入新工程。新的设计不需要维持原模块布局或原回归中的私有 API 行为。

## 3. 分层与依赖规则

```text
宿主绑定 → public C ABI facade → runtime / command queue
                                   │
mihomo config compiler → registry → module config/factory
                                   │
inbound → flow dispatcher → router → outbound（协议或策略组）
              │                          │
         generic relay          injected dialer / transport / session
              │                          │
              └──────── stream / datagram ┘
                                   │
                  executor / timer / DNS / socket service
                                   │
                          platform host callbacks
```

依赖约束：

- public SDK 不包含具体协议 config、libuv、BoringSSL 或 lwIP 类型；共享构建只导出明确声明的 `solaris_*` SDK 符号。
- engine/config/router/relay 依赖模块契约与 registry，不能 include 某个协议的私有头文件。
- adapter 依赖 framework services、I/O 契约与声明的共享 codec/transport。通用服务不反向依赖 adapter。
- 配置编译与模块构造分离：解析配置不能创建 socket；构造对象不能隐式开始联网。
- 平台差异集中在 platform/runtime backend。协议代码不直接调用 JNI、Network Extension、Wintun 或宿主 UI。
- 通用 router 不按协议类型判断 UDP/UoT/QUIC；它查询当前配置下的有效能力和组选择结果。

### 3.1 Solaris 命名与对外入口

| 对象 | 约定与示例 |
| --- | --- |
| C 函数 | `solaris_engine_create`、`solaris_config_compile_yaml`、`solaris_stream_write` |
| C 类型 | `solaris_engine_t`、`solaris_outbound_t`、`solaris_stream_t` |
| 宏、枚举常量与头文件 guard | `SOLARIS_OK`、`SOLARIS_EAGAIN`、`SOLARIS_ENGINE_H` |
| 公共头文件 | `<solaris/engine.h>`、`<solaris/config.h>` 等必要的宿主接口 |
| 构建目标、选项与环境变量 | `solaris_core`、`SOLARIS_ENABLE_TUN` 等；CMake 消费入口 `Solaris::core` |
| 原生库产物 | `libsolaris.so`、`libsolaris.a`、`solaris.dll`、`Solaris.xcframework` |
| 公共组件 | 使用 `solaris_tls_*` 等中立名称；AnyTLS 等名称只用于实际的协议模块 |

清理范围包括自有目录、include 路径、函数/类型/宏、配置标识、日志中的引擎标识、构建脚本、导出表、测试与示例。新工程不携带旧前缀 alias、deprecated wrapper、schema 转换器或 ABI 桥接层；第三方依赖自己的符号和协议标准名称按其原有规范使用，源码来源记录如实保留。

对宿主直接暴露 C 函数与 opaque handle。开发阶段不以 ABI 冻结为前提，不引入 `*_v2` 等历史后缀、`requested_abi_version` 协商或过往函数表。模块 vtable 是与库一同编译的内部源码接口，可随框架迭代调整；它不构成一个独立的动态插件 ABI。类型安全、错误返回、线程与内存所有权仍必须明确。

### 3.2 新工程目录

目录直接按框架边界建立：

```text
include/solaris/              对宿主公开的 C ABI
src/api/                     Solaris C SDK 实现与命令入口
src/runtime/                 executor、任务、取消、预算、对象退役
src/core/                    registry、配置快照、运行实例编排
src/contracts/               内部模块接口：I/O、outbound、inbound、services
src/config/                  mihomo 公共字段、YAML、引用图、诊断
src/flow/                    metadata、dispatcher、TCP relay、连接追踪
src/flow/udp/                association、目的映射、回复端点与 UDP relay
src/router/                  规则解释器、索引、rule-set
src/dns/                     resolver、上游、cache、Fake-IP
src/provider/                provider 调度与资源快照
src/adapters/outbound/ss/     模块 config、factory、会话与协议实现
src/adapters/outbound/vless/
src/adapters/outbound/anytls/
src/adapters/inbound/         socks/http/mixed/tun
src/adapters/policy/          select/url-test/fallback/load-balance
src/transport/               tcp/tls/ws/grpc/xhttp、QUIC session backend
src/codec/                   地址、UoT、XUDP 等可复用 wire codec
src/platform/                socket/接口策略、TUN backend 与平台适配
modules/                     显式模块与构建清单
tests/contracts/             所有 adapter 共用的契约测试
tests/interop/               独立实现对端互通
```

这些目录是新工程的依赖边界。开发从可构建的最小骨架逐步扩展；复用代码进入新目录时适配新契约，不建立平行的 legacy 源码层。测试验证新的框架契约、mihomo 配置语义及网络协议正确性。

## 4. 最小的模块契约集合

| 契约 | 核心职责 | 对新增协议的意义 |
| --- | --- | --- |
| `stream` | 有序字节流、读暂停/恢复、写入、半关闭、背压、关闭屏障 | router/relay 无需识别 SS、VLESS、TLS 或 QUIC stream |
| `datagram` | 保留消息边界、地址、最大消息长度、收发、可选批量发送 | native UDP、UoT、XUDP、QUIC DATAGRAM 对上提供一致语义 |
| `UDP association` | 入站会话身份、固定出站计划、目的映射、超时、有界队列和回复端点 | 同源多目的数据报复用通道；五元组不自动产生独占 socket |
| `outbound` | 查询有效能力，异步打开 stream/datagram，关闭实例 | 协议节点和策略组共用数据面入口 |
| `inbound` | 管理监听/入口，把连接与 metadata 交给 dispatcher | 新入站复用选路、转发、统计与关闭逻辑 |
| `dialer` | 为 adapter 建立到代理服务器或目的地的底层连接 | 统一 DNS、接口、protect、超时和 dialer-proxy |
| `transport factory` | 构建模块允许的 TLS/WS/gRPC/XHTTP 等连接载体 | 多种协议复用相同传输实现 |
| `session` | 管理多 stream/datagram 共用的连接、keepalive、失败传播 | AnyTLS/HTTP2/QUIC 不必伪装成每个 flow 独占 socket |
| `module descriptor` | 类型名、config 编译/释放、实例工厂、依赖与能力元数据 | 新协议可被配置编译器和运行时自动发现 |

接口以 C struct + const vtable + opaque state 实现。只共享真实复用的行为，不设计一个必须实现所有功能的巨型 vtable。规则、DNS upstream、provider 等扩展使用各自的窄接口；复用 registry 的查找/验证基础设施即可，无需统一所有对象的业务方法。

### 4.1 Outbound 接口轮廓

下列是内部源码接口的设计轮廓，省略了类型定义，尚不是可安装的头文件或稳定 ABI：

```c
typedef struct solaris_outbound_ops {
    int (*capabilities)(void *state, const solaris_flow_meta_t *flow,
                        solaris_outbound_caps_t *out);
    int (*open_stream)(void *state, solaris_open_request_t *request);
    int (*open_datagram)(void *state, solaris_open_request_t *request);
    void (*begin_close)(void *state);
    void (*destroy)(void *state); /* 仅在关闭完成且引用归零后调用 */
} solaris_outbound_ops_t;

typedef struct solaris_outbound_module {
    const char *type_name;       /* 例如 mihomo 配置中的 "ss" */
    int (*compile_config)(const solaris_config_view_t *input,
                          solaris_config_compile_context_t *context,
                          solaris_module_config_t **out);
    void (*free_config)(solaris_module_config_t *config);
    int (*create)(const solaris_module_config_t *config,
                  const solaris_module_services_t *services,
                  solaris_outbound_t **out);
} solaris_outbound_module_t;
```

`solaris_open_request_t` 包含 immutable metadata、目标、已固定的 dial plan、deadline、取消令牌、executor 绑定和完成出口。UDP open 请求携带 association 上下文与所需的多目的/映射能力；后续目的数据报不重复执行完整 open/选路。`solaris_module_services_t` 注入 allocator/budget、timer/executor、resolver、dialer、可用的 transport factory 和观测设施，不暴露整个 engine。

`compile_config` 在配置工作任务上执行，无网络副作用；输出模块拥有的不可变配置对象。公共字段先由统一 helper 校验，模块处理自己拥有的字段并报告已消费字段、诊断和引用依赖。跨模块引用由配置编译器解析成有代际生命周期的句柄，不从全局字符串表随用随取。

`create` 在 owner loop 上执行，可分配对象，不发起连接或计时器。候选配置提交后由框架激活其 job scope；懒连接在首次 open 时建立。需要预热的模块向通用 scope 注册任务，失败保持为可观测的预热结果，不冒充配置语法错误。

每个实例包含框架管理的生命周期头、私有 state 和 const vtable。框架统一追踪 child task、连接与引用；`begin_close` 幂等停止新 open 并关闭 session，任务与 I/O 完成后退休引用归零，才调用 `destroy`。模块不能通过直接 free 绕过关闭屏障。

### 4.2 配置、能力与构建注册

配置编译器仅执行 `lookup(type) → compile_config → resolve dependencies → create`。类型别名、公共选项和诊断路径在配置边界归一化。协议私有字段不再塞进全局 union，也不再在 engine 加 `if (type == ...)`。

采用显式静态注册：单一模块清单提供源码、依赖和 descriptor 声明，xmake/CMake 从它生成或读取构建目标与 builtin 列表，并从初始化入口显式引用 descriptor。注册表在构建配置时确定并冻结，重复名称、别名冲突和依赖缺失在初始化时失败。此方式也保证静态链接裁剪不会把只有“自注册 constructor”的模块意外删除。

公开 host SDK 与内部模块契约分离。模块随库一起编译，可裁剪构建直接决定可用 registry。新增普通协议不新增宿主函数，也不要求每种协议新增 SDK enum；两层都不负担原实现的版本兼容机制。

有效能力至少区分：TCP、UDP、域名目标、单/多目的地 UDP、本地映射复用范围、半关闭、批量发送和具体限制。能力来自实现、配置、所选成员及底层服务的交集；例如实现支持 UDP 但 YAML 禁用了 UDP 时应报告不可用。能力查询不联网、不触发健康检查；探测结果属于独立的运行状态。

## 5. 数据面的几个决定性边界

### 5.1 UDP 封装止于 outbound

```text
TUN / SOCKS5 → UDP association → 首次选路并固定 plan → outbound.open_datagram
                       │                                  │
                 目的映射与回复端点          ┌───────────────┼──────────────┐
                                       native UDP     UoT / XUDP    QUIC datagram
```

入站只处理自己的协议格式；它向 outbound 交付目的地址和完整 payload。UoT/XUDP 的 framing、流式解码和协商在 outbound 内完成，共享 codec 可以被多个模块引用。

datagram 的 open 描述是否接受多目的地，以及消息长度、MTU/分片策略等限制。UDP association 由 engine/inbound 命名空间、逻辑客户端身份和源端点确定，五元组只标识目的子流。与核对的 mihomo 行为对齐，association 首次有效报文选路，后续报文解析各自的目标并复用固定出站；不能默认逐目的地重新选路、换节点或创建新 socket。

回复端点保留真实 peer，仅对明确的 DNAT/Fake-IP 映射恢复地址。映射复用与远端过滤分别定义，IPv4/IPv6、零长度报文和超时均为公共 UDP 契约。协议特有的 MTU/分片只在其模块内实现；上层查询有效限制。具体身份、歧义处理与兼容边界见 [UDP / NAT 设计](UDP_NAT_DESIGN.md)。

dispatcher 通过通用策略解析得到 `solaris_dial_plan_t`，固定最终 outbound 引用、策略链、配置代际和 effective capabilities。规则的 UDP 能力检查与实际 open 使用同一 plan。候选计划的查询不应推进 round-robin 等选择状态；最终接受计划时才提交选择。若解析期间遇到快照失效，由策略层重新解析；一旦 plan 被接受，其持有的旧代引用保证打开不会悄悄改成另一成员。

### 5.2 共享拨号与传输组合

所有真实网络 socket 由可注入的 socket service 创建并执行 protect/接口绑定；TCP 在 connect 前、UDP 在首次发送前完成平台策略。TLS、QUIC、Provider HTTP 和 DNS 上游都经过该边界，不能因第三方网络库自行建 socket 而绕过它。

dialer 支持物理网络和经另一个 outbound 建立连接，引用图需要检测策略组与 dialer-proxy 的循环。代理服务器域名的解析策略与业务目标解析分开注入。

transport 提供可组合实现，但组合由配置与模块声明约束。例如 VLESS 可以选择已有 TCP/TLS 或 XHTTP transport；QUIC adapter 使用可提供 stream/datagram 的 session backend。QUIC 在 UDP 上运行，不强制接入“先建 TCP、再套 TLS”的流水线。

Vision 所需的 raw read/write 切换属于显式的窄扩展能力，包含“已有加密数据写完后才切换”的顺序契约。无法提供该能力的 transport 在配置阶段拒绝组合；协议不能通过 `native()` 指针强转去操作另一个模块的私有实现。

### 5.3 策略、观测与协议解耦

策略组实现 outbound 数据面接口，并额外提供自己的 group control interface。健康检查通过统一 open_stream 执行测试请求，统计在公共 flow/stream/datagram 包装层计数，连接管理持有通用连接句柄。

业务字节数与底层传输字节数分开统计，在各自固定边界只计一次；嵌套策略、TLS、Mux 不得重复累加为用户流量。重试只发生在尚未把该次连接交给业务且没有不可重放的业务写入时；健康检查失败与已连接会话断开分别处理。

session owner 负责共享连接故障如何传播至其子流；通用 scheduler 负责 deadline/取消，模块决定协议握手和重连语义，避免框架盲目重放应用数据。

## 6. 异步、所有权和背压契约

这些语义必须先于大批协议实现落到测试中：

- 模块内部操作运行于其对象的 owner executor；一个 engine 可以同时运行多个 I/O worker。TCP 连接、UDP association、共享 session 固定 owner，adapter 实例的可变状态和 session pool 由该 worker 持有。跨线程请求经过有界 mailbox；模块不自行建立一套并发模型。
- 异步 open/write/send 返回 `SOLARIS_OK` 表示请求被接受，完成只通过稍后执行的一次回调交付；返回错误表示没有接受请求且没有后续完成回调。禁止有时同步、有时异步完成造成重入差异。
- 接受的请求必须最终成功、失败或取消完成。请求和 owner scope 持有必要引用，取消之后的迟到 I/O 只能被丢弃或完成清理，不能访问已销毁对象。
- open 完成表示该协议允许使用所返回的 stream/datagram，不承诺远端业务目标健康；握手认证状态在协议能确定时单独报告。
- 内部写入使用引用计数的不可变 buffer slice：成功排队即 retain，完成后释放；拒绝时不持有。宿主边界可以 copy-in，内部不要求每经过一层都复制。
- stream 写入按有界 chunk 接受，队列满返回 `SOLARIS_EAGAIN` 且本次零接受，并提供 writable 通知。read pause/resume 通过包装层传播，避免持续接收并堆积到无界队列。
- datagram 不能按字节部分接受。批量接口可接受有序前缀，返回准确的 accepted 数量；每个已接受消息遵循同一 buffer 生命周期。
- `shutdown_write` 与关闭整个 stream 分开。支持半关闭的协议在写队列排空后发送 FIN；不支持时报告 capability，relay 使用事先定义的兼容策略而非猜测。
- 每个对象有 closing/closed 状态，关闭幂等；完成屏障之后不再访问其回调上下文。停止整个 runtime 只需关闭作用域并等待退役，无需逐协议 switch。

配置对象属于 snapshot；模块实例属于一个 runtime generation；session 属于模块实例；flow 引用本次选定的 generation/实例/session。提交新配置只影响后续选择，旧对象按引用退役，防止 provider 刷新释放正在转发的协议状态。

## 7. 全新框架开发顺序

1. 建立全新 Solaris 目录、构建目标、头文件与导出清单，实现最小 engine 和测试宿主。直接采用新 SDK，不保留原配置/ABI 入口。
2. 定义并实现多 worker executor/mailbox、I/O、任务作用域、取消/关闭屏障和 mock dialer；实现 Direct/Block，使通用 relay 可运行；至少使用两个 worker 验证所有权与停止流程。
   UDP 同时建立 association/mapping/reply-endpoint，用受控双目标对端验证同源映射复用、真实回复地址和有界队列。
3. 建立 registry、公共配置 helper 和模块 factory；YAML 编译器直接生成 Solaris 内部配置对象。
4. 按新契约实现 Shadowsocks、AnyTLS、VLESS，选择性复用通过验证的原算法/codec。UoT/XUDP 归 outbound，TLS/XHTTP 使用中立 transport/session 服务；持续做协议互通回归。
5. 接入通用策略、观测与新配置快照，用混合 native UDP/UoT/XUDP 的组验证能力与选择语义。
6. 新增 SOCKS5 outbound 作为扩展试验，验证只有新模块、注册构建清单、文档和测试需要改动。
7. 通过架构验收后，再扩大 mihomo YAML、DNS/Provider 与协议覆盖。

不要求所有未来扩展点都预先实现。框架的第一轮抽象至少要经 Direct、Shadowsocks、AnyTLS 和 VLESS 这些不同连接/UDP/session 模型验证，避免只围绕最简单的 TCP 协议设计。

## 8. 架构验收与 AI 开发约束

| 验收项 | 证据 |
| --- | --- |
| 新协议不穿透框架 | SOCKS5 outbound 的变更范围中没有 engine/router/TUN/公共 SDK 协议逻辑变更 |
| Solaris 命名与全新接口 | 新源码、安装头文件、导出符号、构建脚本和示例统一命名；无原私有 schema 接口、旧前缀别名或 ABI 适配层 |
| 配置自包含 | 新类型可被 registry 查询、校验、构造、裁剪；禁用模块时给出明确配置错误 |
| 通用行为自动适用 | 新节点参与 select、测速、流量统计、连接关闭，无新增类型特判 |
| UDP 统一 | TUN 和 SOCKS5 不 include UoT/XUDP/具体出站私有头；异构组 TCP/UDP 测试通过 |
| UDP 会话语义 | 同源多目的复用、入站隔离、首包选路固定、DNAT/Fake-IP 恢复、空包/IPv6 与实际超时测试通过 |
| 生命周期统一 | 每个 adapter 运行同一套取消、超时、背压、半关闭、重复关闭、停止中完成、旧代退役测试 |
| 多核与对象归属 | 两个以上 worker 可并行运行；同一 TCP/UDP association/session 不漂移或并发操作同一状态；共享栈 backend 线程约束可检查 |
| 依赖边界可检查 | 构建 target 与静态 include 检查禁止跨层私有依赖，显式登记例外 |
| 协议行为真实 | 独立实现互通、畸形输入 fuzz、ASan/UBSan；共享契约测试不能替代 wire 协议测试 |
| 库可消费 | 安装包下游链接、导出符号、平台绑定 smoke 与真实 VPN 测试分别验收 |

每个 AI 实现任务先固定该模块的 descriptor、使用的服务、状态机、buffer/对象所有权和测试对端。任务完成必须同时报告契约测试和独立互通结果；遇到契约无法表达的行为时先修改架构提案与公共测试，再实现扩展，不能在通用模块暗加协议特判。

## 9. mihomo 参考

固定参考提交：`9f121787bb563fe655d2789cbf6dbcc7ae19a0c9`。

- [constant/adapters.go](https://github.com/Herta-Network/mihomo/blob/9f121787bb563fe655d2789cbf6dbcc7ae19a0c9/constant/adapters.go)：统一 ProxyAdapter、Dialer、Conn/PacketConn 与能力查询。
- [adapter/outbound/base.go](https://github.com/Herta-Network/mihomo/blob/9f121787bb563fe655d2789cbf6dbcc7ae19a0c9/adapter/outbound/base.go)：公共选项、拨号配置、连接包装与资源持有。
- [adapter/parser.go](https://github.com/Herta-Network/mihomo/blob/9f121787bb563fe655d2789cbf6dbcc7ae19a0c9/adapter/parser.go)：按协议解码并调用构造器。该实现仍有集中式类型分支；本提案借鉴其接口边界，用 C descriptor/registry 进一步收拢注册与配置职责。

借鉴的重点是把协议变化限制在 adapter 边界。C 实现使用显式作用域、引用、函数表和状态机承接 Go 中由接口、context 与运行时承担的职责。
