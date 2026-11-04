# Solaris Core 开发计划

更新日期：2026-11-03。本文件是实现进度与阶段状态的唯一维护位置。

## 1. 当前状态

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| 目标、框架、SDK、UDP/NAT 与多核设计整理 | 已完成文档基线 | 见 [文档索引](../README.md) |
| 历史文档归档 | 已完成 | 原 README、嵌入说明、四份草案与调查证据 |
| M0–M6 新工程实现 | 全部未开始 | 现有源码仍是原实现，不计为新框架已完成 |
| 新工程契约/差分/互通/设备/性能验收 | 未执行 | 历史 smoke 和探针不计入新验收 |

本计划不承诺未经测量的工期和吞吐。各阶段按依赖与验收推进；普通开发不要求保留原接口兼容。

## 2. 阶段依赖与交付目标

```mermaid
flowchart LR
    M0[M0 工程与 SDK 骨架] --> M1[M1 可扩展多 worker 框架]
    M1 --> M2[M2 YAML 与基础业务闭环]
    M2 --> M3[M3 DNS / 双栈 TUN]
    M3 --> M4[M4 日常配置覆盖]
    M4 --> M5[M5 协议 / 平台扩展]
    M5 --> M6[M6 高级协议与性能]
```

| 阶段 | 可交付结果 | 退出门槛 | 当前状态 |
| --- | --- | --- | --- |
| M0 | 正常构建、安装、调用的新 Solaris 最小库 | G-BUILD、基础 G-LIFE | 未开始 |
| M1 | 模块注册、统一 I/O、UDP association、至少两个 workers；新增协议不改通用层 | G-MODULE、G-LIFE、G-WORKER、基础 G-UDP/G-INTEROP | 未开始 |
| M2 | 宿主可加载基础 mihomo YAML、代理、切组、查询与关闭连接 | G-CONFIG、G-RELOAD、已声明协议 G-INTEROP | 未开始 |
| M3 | DNS/Fake-IP、双栈 TUN 与 Android/Apple VPN 闭环 | 完整基础 G-UDP、相关 G-DEVICE | 未开始 |
| M4 | Provider、完整常用策略组、Geo/rule-set 与日常配置样本覆盖 | 扩展 G-CONFIG/G-RELOAD/G-INTEROP | 未开始 |
| M5 | 更多协议/传输与 Windows/Linux/OpenHarmony 集成 | 新增组合 G-INTEROP、各平台 G-BUILD/G-DEVICE | 未开始 |
| M6 | QUIC 等高级能力、栈扩展和有测量依据的性能策略 | 对应 G-INTEROP/G-DEVICE/G-PERF | 未开始 |

门槛定义见 [测试规范](TESTING.md)。M2 是首个宿主业务可用的基础库目标；M4 是日常配置覆盖目标。任何阶段都不能自动推导成全量 mihomo 功能兼容。

## 3. M0：新工程与 SDK 骨架

| 任务 | 交付物与范围 | 验收 |
| --- | --- | --- |
| M0-01 | 确定主构建入口、单一模块清单格式、YAML/JSON 库与依赖固定方式；记录取舍 | 选型可覆盖目标平台，模块源码/依赖不维护重复清单 |
| M0-02 | 建立 Solaris 目录与最小构建目标；自有命名、头文件、导出、示例统一 | 新构建不编入原框架；无旧前缀别名/桥接；来源声明保留 |
| M0-03 | 定义 engine/host/options/error/snapshot 的最小 C SDK，所有权与线程约定 | create/stop/destroy、错误和回调屏障 smoke 通过 |
| M0-04 | 库安装与独立消费样例、产物命名、依赖链接和导出检查 | 消费者只用安装目录即可编译链接运行 |
| M0-05 | 建立测试入口、CI 基础与可注入时钟/失败工具 | 在本机和首个 CI 平台执行 G-BUILD/基础 G-LIFE |
| M0-06 | 固定参考提交、依赖与构建开关；建立配置/协议兼容矩阵初版 | 每条支持状态能关联到计划任务或测试；未验证项明确 |
| M0-07 | 确定首个 TUN backend 的状态隔离、packet 接口与栈 owner 边界 | 原 lwIP 若复用则明确串行约束；多 worker 不直接访问全局栈 |

原 SDK 的缺失链接问题可作为经验，不要求先修好旧构建才开始新工程。原可复用代码进入新目录时接受新命名与契约，不设置长期平行的 legacy 实现层。

## 4. M1：证明框架成立

| 任务 | 交付物与范围 | 验收 |
| --- | --- | --- |
| M1-01 | 多 worker executor、mailbox、timer、取消、generation、scope 与关闭屏障 | 至少两 workers；无丢唤醒/重复完成；关闭中释放与通知可完成 |
| M1-02 | stream/datagram、owned buffer、背压、半关闭、accepted batch 契约 | 公共 I/O 契约测试与内存检查 |
| M1-03 | registry、module descriptor、配置视图/helper、factory 和静态裁剪 | 新类型可注册/构造/禁用；重复名与依赖错误准确 |
| M1-04 | 统一 dialer/socket 服务、最小 resolver、protect 与网络绑定；Direct/Block | TCP/UDP 本地对端；失败/取消时 socket 生命周期正确 |
| M1-05 | UDP association、目的映射、reply endpoint、worker 归属与 deadline | U01–U04、U08 及 U09/U10/U12 的数据报子集 |
| M1-06 | 中立 TLS/transport/session 边界；按新契约接入 SS、AnyTLS、VLESS 基础组合 | 至少覆盖普通流、原生 UDP、流式 UDP 与共享 session 的不同模型 |
| M1-07 | 最小 select/计划固定、通用单次测速、流量与连接追踪 | 不按协议分支实现；统计不重复，健康/选择状态区分 |
| M1-08 | 增加 SOCKS5 outbound 作为扩展试验 | 仅模块、注册/构建清单、测试/文档变化；TCP/UDP、选择、测速、关闭通过 |

M1 的模块配置可以由测试视图构造，完整 YAML/策略控制在 M2。接口必须经不同协议模型验证，不能只以 Direct 或纯 TCP 协议认定框架完成。

## 5. M2：基础配置和宿主业务闭环

| 任务 | 交付物与范围 | 验收 |
| --- | --- | --- |
| M2-01 | YAML 编译、源位置诊断、默认值、公共/模块字段、引用图和能力校验 | 固定样本差分；错误配置不静默降级 |
| M2-02 | 顺序路由解释器、metadata、基础域名/CIDR/网络/端口/MATCH、rule/global/direct | 首匹配、延迟解析、no-resolve 与 UDP 过滤用例 |
| M2-03 | 基础协议 YAML→registry→运行时接通，安全/传输组合逐项登记 | 支持列表没有“有代码但入口不可达”的项目 |
| M2-04 | SOCKS5/HTTP/mixed 入站、多入站、认证和统一 TCP/UDP 转发 | 宿主可实际代理；SOCKS UDP 与 TUN 目标接口共用 association |
| M2-05 | 组/节点控制、测速、统计、连接快照、关闭、日志与事件 SDK | 客户端不需要 HTTP 控制器即可使用完整基础功能 |
| M2-06 | prepare/commit/retire、候选失败保持现状、监听变更计划 | 既有 TCP/UDP 不被错误释放或悄悄换 plan |
| M2-07 | 宿主样例加载一份基础 mihomo YAML 完成代理与控制 | G-CONFIG、G-RELOAD 和声明组合的互通证据完整 |

## 6. M3：DNS 与双栈 VPN

| 任务 | 交付物与范围 | 验收 |
| --- | --- | --- |
| M3-01 | DNS 报文、UDP/TCP 上游、hosts/cache、policy 与代理服务器独立解析 | 受控 DNS 对端、缓存失效和解析依赖环用例 |
| M3-02 | DoH/DoT、fallback、系统 DNS/网络变化 | 使用统一网络策略；不阻塞 I/O owner |
| M3-03 | Fake-IP 分配/租约/排除/持久化边界、UDP DNAT 与歧义隔离 | U07，更新与重启不错误复用活跃映射 |
| M3-04 | 双栈 TUN packet codec、TCP 栈 backend、UDP 接入和 sniff | IPv6/空包/校验和/MTU/分片能力如实体现 |
| M3-05 | Android fd/protect、Apple packet callback 与薄绑定 | 真机或明确标注的对应设备验证，签名/模拟器不冒充真机 |
| M3-06 | 断网恢复、前后台、重复启停、回调排空和 TUN 资源释放 | 相关 G-LIFE/G-WORKER/G-UDP/G-DEVICE 通过 |

## 7. M4：日常配置覆盖

| 任务 | 交付物与范围 | 验收 |
| --- | --- | --- |
| M4-01 | 资源后端与 proxy/rule Provider 调度、下载、解析、过滤、原子发布 | 失败保留已生效内容，无半更新状态 |
| M4-02 | url-test/fallback/load-balance、嵌套组、健康历史与全局一致选择 | 超时/取消/懒检查/成员刷新用例；多 worker 语义一致 |
| M4-03 | Geo/RULE-SET、逻辑规则、源地址/进程/UID 条件；格式逐项登记 | 顺序与解析语义保持；缺平台能力明确诊断 |
| M4-04 | profile 选择/映射持久化、Provider 独立 revision 与应用流程 | 更新不重启整个 TUN；崩溃/错误时保持可恢复状态 |
| M4-05 | 日常配置语料回归与兼容矩阵更新 | 以样本和组合覆盖说明“日常可用”，列出剩余缺口 |

## 8. M5–M6：扩展与性能

| 任务 | 阶段 | 交付与验收 |
| --- | --- | --- |
| M5-01 | M5 | HTTP outbound、Trojan、VMess 等增量模块；每个模块经过 G-MODULE/G-INTEROP |
| M5-02 | M5 | WS/gRPC/HTTP Upgrade/XHTTP 与额外安全/指纹组合；矩阵逐项验证，不推断任意组合 |
| M5-03 | M5 | Windows/Linux/OpenHarmony 宿主接口、绑定与产物；各平台独立构建和设备验收 |
| M5-04 | M5 | 其他 mihomo 协议需求进入独立模块任务，包括 Snell/SSR/WireGuard/Naive 等需要专门后端的能力；先记录依赖与支持边界 |
| M6-01 | M6 | QUIC backend、Hysteria2/TUIC/DoQ/HTTP3 等按实际需求顺序接入，不能绕过 socket/protect 服务 |
| M6-02 | M6 | 额外链式代理、更多高级规则与协议组合；不突破公共依赖边界 |
| M6-03 | M6 | 串行栈瓶颈测量、可隔离/分片栈后端验证及 worker 分配优化 |
| M6-04 | M6 | 1/2/4 workers、普通/批量 I/O、单流/多流/Mux 性能测量；以数据确定默认值与预算 |

以上是覆盖路线，不是“阶段结束即全量支持所有 mihomo 版本”的声明。未排定或尚无独立互通证据的协议继续保留在兼容矩阵的未支持/未验证项。

## 9. 第一批可执行工作

下一轮从 M0-01、M0-06、M0-07 的决策记录开始，随后实现 M0-02–M0-05 的最小 Solaris 库与安装消费样例。该批完成前不批量扩展协议。

随后进入 M1-01/M1-02/M1-04 的最小多 worker Direct 数据路径，用本地受控对端验证线程归属与释放；接着完成 registry、UDP association 和模块扩展试验。运行时与 UDP 的关键接口不能等到功能铺满后再重构。

## 10. AI 辅助开发工作单

每项实现任务附带以下内容，任务大小以能独立审查和验收为准：

```text
任务 ID / 对应阶段：
目标行为与不支持的组合：
前置任务与参考规范：
允许变更的模块、注入服务与依赖：
状态机、owner、buffer/对象所有权：
错误、取消、背压、关闭与配置更新行为：
测试 ID、独立对端、失败注入场景：
本次结果、证据、剩余限制：
```

AI 先核对契约，再实现小步变更；发现契约无法表达协议行为时，更新责任文档和公共测试。不得把协议特判、无界队列或隐式跨线程访问加回通用层来绕过问题。

阶段完成需要交付物与证据一并满足。填写通过/失败/未执行，不能把编译通过写成互通通过，也不能用本地模拟替代真实平台。文档、兼容矩阵和任务状态随实际结果更新。
