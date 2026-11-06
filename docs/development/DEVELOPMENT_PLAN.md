# Solaris Core 开发计划

更新日期：2026-11-05。本文件是实现进度与阶段状态的唯一维护位置。

## 1. 当前状态

| 项目 | 状态 | 说明 |
| --- | --- | --- |
| 目标、框架、SDK、UDP/NAT 与多核设计整理 | 已完成文档基线 | 见 [文档索引](../README.md) |
| 历史文档归档 | 已完成 | 原 README、嵌入说明、四份草案与调查证据 |
| M0 新工程骨架、Solaris 命名与基础 SDK | 已提交并推送 `8fa5180`，CI 通过 | 新 CMake/模块清单、私有 libuv、异步生命周期与安装消费 |
| M1 框架与首批数据面 | M1-01–M1-08 的实现与本机功能验收完成 | 四种构建各 40 项；外部重复互通限制见最终记录 |
| M2–M6 | 未开始 | 下一阶段为 YAML、路由、入站与宿主业务 API；不从 M1 推导支持 |
| 新 SDK/生命周期/安装消费验收 | macOS arm64 通过 | 共享/静态、完整 40 项、独立 C/C++ 消费、ASan/UBSan 与 TSan；详见最终记录 |
| 远端 CI | M0 CI 通过；M1 远端 CI 尚未验收 | 不把 M0 的通过状态延伸到新代码 |
| 代理协议互通、设备与性能验收 | M1 声明组合的常规互通通过；设备/性能未验收 | 长重复 Xray UDP 存在独立控制端也可复现的外部限制，不宣称生产稳定性 |

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
| M0 | 正常构建、安装、调用的新 Solaris 最小库 | G-BUILD、基础 G-LIFE | 已完成本机与 CI 验收 |
| M1 | 模块注册、统一 I/O、UDP association、至少两个 workers；新增协议不改通用层 | G-MODULE、G-LIFE、G-WORKER、基础 G-UDP/G-INTEROP | 实现与本机功能验收完成；远端 CI 未运行，长重复限制见下文 |
| M2 | 宿主可加载基础 mihomo YAML、代理、切组、查询与关闭连接 | G-CONFIG、G-RELOAD、已声明协议 G-INTEROP | 未开始 |
| M3 | DNS/Fake-IP、双栈 TUN 与 Android/Apple VPN 闭环 | 完整基础 G-UDP、相关 G-DEVICE | 未开始 |
| M4 | Provider、完整常用策略组、Geo/rule-set 与日常配置样本覆盖 | 扩展 G-CONFIG/G-RELOAD/G-INTEROP | 未开始 |
| M5 | 更多协议/传输与 Windows/Linux/OpenHarmony 集成 | 新增组合 G-INTEROP、各平台 G-BUILD/G-DEVICE | 未开始 |
| M6 | QUIC 等高级能力、栈扩展和有测量依据的性能策略 | 对应 G-INTEROP/G-DEVICE/G-PERF | 未开始 |

门槛定义见 [测试规范](TESTING.md)。M2 是首个宿主业务可用的基础库目标；M4 是日常配置覆盖目标。任何阶段都不能自动推导成全量 mihomo 功能兼容。

## 3. M0：新工程与 SDK 骨架

| 任务 | 交付物与范围 | 验收 | 状态 |
| --- | --- | --- | --- |
| M0-01 | 确定主构建入口、单一模块清单格式、YAML/JSON 库与依赖固定方式；记录取舍 | 选型可覆盖目标平台，模块源码/依赖不维护重复清单 | 已完成：CMake、JSON 清单、依赖 lock；解析器尚未链接 |
| M0-02 | 建立 Solaris 目录与最小构建目标；自有命名、头文件、导出、示例统一 | 新构建不编入原框架；无旧前缀别名/桥接；来源声明保留 | 已完成，新源码/导出无旧命名 |
| M0-03 | 定义 engine/host/options/error/snapshot 的最小 C SDK，所有权与线程约定 | create/stop/destroy、错误和回调屏障 smoke 通过 | 本机通过 |
| M0-04 | 库安装与独立消费样例、产物命名、依赖链接和导出检查 | 消费者只用安装目录即可编译链接运行 | 本机共享/静态及搬迁消费通过 |
| M0-05 | 建立测试入口、CI 基础与可注入时钟/失败工具 | 在本机和首个 CI 平台执行 G-BUILD/基础 G-LIFE | M0 本机与 CI 均通过 |
| M0-06 | 固定参考提交、依赖与构建开关；建立配置/协议兼容矩阵初版 | 每条支持状态能关联到计划任务或测试；未验证项明确 | 已完成初版 |
| M0-07 | 确定首个 TUN backend 的状态隔离、packet 接口与栈 owner 边界 | 原 lwIP 若复用则明确串行约束；多 worker 不直接访问全局栈 | 已完成边界设计，backend 代码待 M1/M3 |

原 SDK 的缺失链接问题可作为经验，不要求先修好旧构建才开始新工程。原可复用代码进入新目录时接受新命名与契约，不设置长期平行的 legacy 实现层。

工程决策见 [M0 决策记录](M0_DECISIONS.md)，当前 API 见 [SDK](SDK.md)，支持范围见 [兼容矩阵](COMPATIBILITY.md)。

### 本次本机验证记录

环境：macOS arm64、AppleClang 21.0.0、CMake 4.4.5、Ninja；libuv 1.53.0 固定归档。历史文档基线为 `532c13a`，本节验证记录随 M0 实现提交保存，对应该提交的源码。

| 构建目录 | 检查 | 结果 |
| --- | --- | --- |
| `build-m0-shared` | Debug 共享库、SDK smoke、8 组生命周期契约、9 个导出、搬迁后的 C/C++ 消费、最小宿主 | 通过 |
| `build-m0-static` | Debug 静态库、SDK smoke、相同生命周期契约、搬迁后的 C/C++ 消费 | 通过 |
| `build-m0-asan` | ASan/UBSan、SDK/生命周期、导出与安装消费 | 通过；消费测试已使用配对 C/C++ 工具链复测 |
| `build-m0-tsan` | TSan 下的 SDK smoke 与生命周期契约 | 通过 |

标准复现步骤见 SDK 文档。Sanitizer 构建使用 `-DSOLARIS_SANITIZER=address|thread`，并通过 `FETCHCONTENT_SOURCE_DIR_SOLARIS_UV` 复用共享构建已校验的依赖源码。日志位于对应构建目录的 `Testing/Temporary/LastTest.log`；配置/编译日志位于 `build-m0-bootstrap/`。

本节是提交前的本机证据，远端 CI 结果在实际运行后单独记录。尚无其他 OS 本机验证、协议互通、系统 VPN 或性能测量结果。M0 支持一个控制 worker，不计为 M1 的多 worker 验收。

## 4. M1：证明框架成立

| 任务 | 交付物与范围 | 验收 | 状态 |
| --- | --- | --- | --- |
| M1-01 | 多 worker executor、mailbox、timer、取消、generation、scope 与关闭屏障 | 至少两 workers；无丢唤醒/重复完成；关闭中释放与通知可完成 | 本机通过：多 worker/scope/deadline/barrier |
| M1-02 | stream/datagram、owned buffer、背压、半关闭、accepted batch 契约 | 公共 I/O 契约测试与内存检查 | 本机通过：stream/datagram/buffer 与背压 |
| M1-03 | registry、module descriptor、配置视图/helper、factory 和静态裁剪 | 新类型可注册/构造/禁用；重复名与依赖错误准确 | 本机通过：冻结 registry、配置/实例所有权、失败回收与三种裁剪组合 |
| M1-04 | 统一 dialer/socket 服务、最小 resolver、protect 与网络绑定；Direct/Block | TCP/UDP 本地对端；失败/取消时 socket 生命周期正确 | 本机通过：Direct/Block、系统解析、同步 socket 策略与本地 bind |
| M1-05 | UDP association、目的映射、reply endpoint、worker 归属与 deadline | U01–U04、U08 及 U09/U10/U12 的数据报子集 | 本机通过：关联隔离/合并、固定 owner/plan、双栈/域名、真实源端口、deadline/关闭与失败回收 |
| M1-06 | 中立 TLS/transport/session；VLESS 基础协议、encryption、Vision、XUDP；SS 原生 UDP/UoT；AnyTLS/session/UoT | 下表逐项验收，覆盖普通流、协议加密/raw 切换、原生/流式 UDP 与共享 session | 已接入全部子项，常规互通/边界测试通过；长重复外部限制单独记录 |
| M1-07 | 最小 select/计划固定、通用单次测速、流量与连接追踪 | 不按协议分支实现；统计不重复，健康/选择状态区分 | 已实现：共享选择、固定 plan、独立健康、观测/关闭、物理计数和 HTTP(S) probe；本机验证通过 |
| M1-08 | 增加 SOCKS5 outbound 作为扩展试验 | 仅模块、注册/构建清单、测试/文档变化；TCP/UDP、选择、测速、关闭通过 | 本机通过：CONNECT/UDP ASSOCIATE、认证、控制连接、失败回收及独立裁剪 |

M1 的模块配置可以由测试视图构造，完整 YAML/策略控制在 M2。接口必须经不同协议模型验证，不能只以 Direct 或纯 TCP 协议认定框架完成。

### M1-06 协议范围与退出条件

协议按家族分目录，边界见 [架构规范](ARCHITECTURE.md#协议家族与组合)。以下子项全部属于 M1-06，不能把裸 VLESS/TLS 的通过记录当成 VLESS 家族已完成，也不能仅凭 AnyTLS UoT 覆盖 SS UoT。

| 子项 | 必须交付与验收 | 当前状态 |
| --- | --- | --- |
| M1-06a 共用 transport | carrier/TLS/record filter；session 与 raw 切换窄接口的所有权、背压、故障和退休验证 | carrier/TLS/filter/session 与方向独立的 raw 切换已实现并验证 |
| M1-06b 裸 VLESS | 无 encryption/flow 的基础协议，plain/TLS carrier 的双 worker、双栈、域名、错误认证与关闭 | 已实现并通过本机独立对端 |
| M1-06c VLESS encryption | 独立加密层与配置校验；固定 Xray 对端的握手、认证、记录边界、篡改/重放、超时/取消；启用的会话恢复模式逐项验证 | 已实现三种 appearance、1-RTT/0-RTT、双类认证密钥及 relay；固定 Xray 互通、独立 crypto fixture 和生命周期本机通过 |
| M1-06d Vision | `xtls-rprx-vision` 的 flow、padding、内层 TLS 识别、raw 切换及缓冲交接；TLS 与 encryption 承载组合分别验证，明确 UDP 443 语义 | 已实现；真实内层 TLS 的双向 raw、padding/识别、TLS/encryption 组合和 UDP 443 策略本机通过 |
| M1-06e VLESS XUDP | VLESS 的 datagram 路径采用 XUDP；双栈/域名、多目的、真实回复地址、空包、拆粘包/截断、session 故障及 association 关闭 | Single XUDP 已实现，plain/TLS、独立 codec、双 worker/双栈/domain、异常帧与 association 组合本机通过 |
| M1-06f SS TCP/native UDP | 当前五种 cipher 的 TCP、原生 UDP、重放状态及生命周期 | 已实现并通过本机独立对端与异常报文测试 |
| M1-06g 共享 UoT | UoT v2 codec/流式 datagram backend；分别接入 SS 加密 stream 与 AnyTLS 子流；每个支持的 SS cipher 运行 UoT 互通与取消/背压/关闭测试 | 共享 backend/codec 的 SS/AnyTLS 接入已实现并通过本机互通；三种代理封装的 association 组合已验证 |
| M1-06h AnyTLS/session | TLS、认证、padding、session 复用与故障传播；通过共享 UoT 提供 datagram | AnyTLS v2/TCP/UoT 已实现并通过本机互通及 session/codec 边界测试 |

每个组合必须通过配置→registry→工厂入口，并声明有效能力；不支持的 encryption/flow/UDP 方案明确拒绝，不能静默降级。协议加密、flow、carrier 和 UDP 封装分别登记，不宣称任意组合可用。XUDP/UoT 的 U06 内部数据路径在 M1 验收，YAML/入站接入在 M2 验收。逐项测试要求见 [测试规范](TESTING.md#6-协议与解析器)。

M1 功能范围已实现；未实现功能没有新增配置入口或占位成功路径。TLS 扩展的版本、补丁及协议边界见 [TLS 后端](TLS_BACKEND.md)。


### M1 首批验证记录（2026-11-04）

实现边界与内部接口见 [M1 数据路径](M1_DATA_PATH.md)。首批对应 M1-01/M1-02/M1-04，不代表整个 M1 完成。

- `sdk_smoke` 与原有 8 组生命周期契约继续通过。
- `executor_contract`：5 组 worker/scope/deadline/buffer 契约，包括 192 个 scope 的分批排空。
- `io_contract`：独立 Python 对端验证 6 个 TCP 场景、3 个 UDP 场景，以及拒绝、deadline、活动通道停止。覆盖 IPv4/IPv6、localhost、半关闭、背压、空包、备用源端口与同通道多目标复用。
- macOS arm64 的共享/静态安装消费、ASan/UBSan、TSan 验证通过。当前代码尚未提交/推送，不宣称 M1 的远端 CI 已通过。

构建目录沿用 `build-m0-shared`、`build-m0-static`、`build-m0-asan`、`build-m0-tsan`；这些目录现在对应 M1 工作区，不再是 M0 的冻结产物。M0 的固定证据是提交 `8fa5180` 和 [CI run 41763575334](https://github.com/Anti-EntropyTech/Solaris-Core/actions/runs/41763575334)。M1 日志在各目录的 `Testing/Temporary/LastTest.log`，编译日志在 `build-m0-bootstrap/m1-*.log`。

### M1-03 验证记录（2026-11-05）

- `module_contract` 通过：新增测试 descriptor 的注册/构造，重复规范名/别名、缺失依赖、依赖环、未知/禁用类型、配置类型/范围/字段诊断；配置在输入修改及 registry 销毁后有效，双 worker 使用同一不可变配置，异步实例资源随 retire/stop 排空。
- 注入 registry、配置 wrapper/payload、实例 wrapper/state 的分配失败，以及模块编译/工厂部分成功后失败；返回空输出，已分配状态清理，预算归零，无拒绝后的 on_close。
- Direct/Block 的 `io_contract` 改为经 registry→配置→工厂打开 TCP/UDP；编译的队列限制/deadline、注入 socket policy、本地 bind 与实例先退休/通道继续工作均通过。
- macOS arm64 共享构建全套测试、静态构建全套测试及安装 C/C++ 消费通过；ASan/UBSan 与 TSan 的 `module_contract`、`io_contract` 通过，新增分配失败用例另行复测通过。
- `build-m1-direct-only`、`build-m1-block-only`、`build-m1-no-outbounds` 三种静态裁剪构建各通过全部 7 项测试；registry 内容、archive/最终可执行文件的 descriptor 符号和安装消费均符合开关。
- 复现：正常构建使用 README 命令；裁剪增加 `-DBUILD_SHARED_LIBS=OFF -DSOLARIS_ENABLE_DIRECT=ON|OFF -DSOLARIS_ENABLE_BLOCK=ON|OFF`。ASan/TSan 使用既有 sanitizer 开关。CI 已加入裁剪矩阵，但本次未提交/推送，未运行远端 CI。

M1-03 通过不等于 G-MODULE 完整通过；新增 SOCKS5 的扩展试验仍属于 M1-08。

### M1-05 验证记录（2026-11-05）

- `udp_association_contract`：独立 Python 对端核对 A/B/A 本地端口复用；相同源地址在不同 engine/入站隔离；8 个并发提交合并为一个关联并按上限接纳 3 个；worker 集合由 2 改为 1 时存量不迁移、新关联使用新集合。
- 同一关联经过数值 IPv4、localhost 解析和 IPv6 空报文；备用源端口原样回复；映射/队列/消息长度限制、batch 前缀、拒绝计数、端点引用、固定 plan、预算归零通过。备用 IP 的元数据传递由受控通道补测，不声称 macOS loopback 上已运行备用 IP 网络对端。
- `udp_lifecycle_contract`：open 超时及成功回调先于 timer 处理的迟到成功、DNS 迟到/停止后完成、scope 建立前的排队首包停止、idle 不被队列满或回复拒绝延长、单目的子通道、旧 ID/回复 generation、选路拒绝、scope 上限、关联/请求/映射分配失败。拒绝无回调，接受恰好一次完成，stop 等待实际回调排空。
- 共享/静态构建各 10 项测试、C/C++ 安装消费通过；ASan/UBSan 与 TSan 的模块和 UDP 两组契约通过。三种裁剪配置重新验证：仅 Direct 9 项、仅 Block 8 项、全部关闭 8 项均通过；association 公共层不依赖某个 adapter。
- 测试脚本、断言与日志是本机工作区证据；未提交/推送，未执行远端 CI、代理协议互通、TUN/设备或性能验收。

### M1-06 当前验证（2026-11-05，阶段仍未完成）

- 中立 TLS 使用固定 BoringSSL、私有符号、有限 BIO pair 和明文队列；OpenSSL 对端通过证书身份/信任拒绝、超时、取消、暂停、背压、截断与关闭。TLS 自有代码的 ASan/UBSan、TSan 通过；BoringSSL 内部堆不计入 Solaris buffer budget。
- VLESS TCP 和普通 TLS 经 registry/factory 接入；固定 sing-box v1.12.12 独立对端验证双 worker、IPv4/IPv6/domain、内容完整性、半关闭、错误凭据与取消。受控对端补充拆分 header/addons、错误版本、截断 header 与无响应 EOF；ASan/UBSan、TSan 的同组互通测试通过。仅支持十六进制 UUID、无 flow/附加安全层；不声明 VLESS UDP、Vision/REALITY 等组合。
- 共享/静态各 13 项本机检查通过，包括私有 TLS/crypto 符号隔离及搬迁消费。静态纯 C 宿主强制链接整个 core archive，验证可选模块依赖；安装不暴露 BoringSSL/libuv 头文件。新增协议尚未提交/推送或运行远端 CI。
- SS 支持 aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、2022-blake3-aes-128-gcm 和 2022-blake3-aes-256-gcm，TCP/native UDP 均经 registry/factory 和双 worker 独立对端验证。UDP 覆盖同族 A/B/A、IPv6 lane、域名首包、空包、6 KiB 实际回包、背压、错误凭据及取消；65,000 字节协议 payload 边界用独立 Go 加密 fixture 验证，未宣称本机网络可发送该尺寸。
- 独立 fixture 验证 TCP tag/长度/截断/响应请求 salt/时间边界，UDP tag/type/time/client session/address、重复/过旧 packet ID、两组 server session 保留与容量/分配失败；共享 exact replay store 验证并发唯一接纳和满表拒绝。ASan/UBSan 与 TSan 的 SS 和 VLESS 互通/codec 测试通过。
- sing-box v1.12.12 在本机同一 UDP 映射先数值 IPv4 后 IPv6 或域名不回包；独立 sing-shadowsocks v0.2.8 客户端对同一 peer 复现，独立 IPv6 映射及域名首包成功。该限制不通过改写客户端目标或首包 source 隐藏。
- SS 新增后共享构建完整 15 项通过；静态运行时/符号 14 项通过，安装消费发现 Threads 导出依赖遗漏，修复后单独重验通过。新增独立 BLAKE3 符号审计通过；仅 SS 出站的静态裁剪构建完整 13 项通过。新增协议未提交/推送或运行远端 CI。
- VLESS encryption/Vision/XUDP、UoT 的 AnyTLS/association 接入、AnyTLS/session 与 M1-07/M1-08 尚未完成；以上记录不代表 M1 退出门槛通过。

目录重构后（2026-11-05），macOS arm64 共享构建全套 16 项、静态构建相关 9 项通过，包含 VLESS/SS 互通、SS codec、模块/密码符号与安装消费。源码对照确认 SS 仅改变路径/include，VLESS 仅拆分模块与基础 codec；本次未新增协议能力或重跑 sanitizer。日志为 `build-m0-bootstrap/m1-layout-{shared,static}-{configure,build,test}.log`。

组件归组后（2026-11-05），API、core/contracts、runtime、config、transport、DNS/codec、Direct/Block、测试与验证脚本按职责分目录。源码/构建内容对照确认只调整路径与安装验证脚本的仓库根定位；共享/静态全套各 16 项、全部出站关闭 8 项、仅 SS 13 项通过。日志为 `build-m0-bootstrap/m1-components-*.log`。

共享 UoT/SS 接入后（2026-11-05）：共享与静态构建全套各 18 项通过；ASan/UBSan、TSan 的 UoT codec、流式 datagram lifecycle、SS codec 与 SS native/UoT 互通通过。错误凭据用例补充了 stream 在写入完成前被对端拒绝的合法失败结果，sanitizer 互通复测通过；没有 sanitizer 报告。日志为 `build-m0-bootstrap/m1-uot-*.log`。AnyTLS、XUDP 及代理 association 的组合验收仍待完成。

AnyTLS/session 接入后（2026-11-05）：共享与静态完整构建各 21 项通过；全出站/TLS 关闭的静态裁剪 11 项通过。新增 session 契约验证多子流、最新空闲 session、deadline、分配失败、部分帧取消及 stop 等待；AnyTLS codec/固定独立对端验证 v2、padding 更新、TCP/UoT、复用和畸形响应。最终 diagnostic sink/队列默认值补充后，ASan/UBSan 与 TSan 的这三组测试重新通过，静态同三组及安装消费重新通过；无 sanitizer 报告。日志为 `build-m0-bootstrap/m1-anytls-*.log` 与 `m1-session-*.log`。尚未完成 VLESS encryption/Vision/XUDP、代理 association 组合或 M1-07/M1-08；没有远端 CI/设备/性能结论。

### XUDP 与 U06 代理 association 验证（2026-11-05）

- VLESS CommandMux 3 与独立 XUDP codec 已接入共享流式 datagram backend，未在通用 association 中增加协议分支。Single XUDP 的每个 datagram channel 拥有一条承载流，session ID 为 0；本阶段没有跨连接重连/global-ID 恢复。
- `xudp_codec_contract` 与 `xudp_stream_contract`：独立 Python fixture 覆盖 IPv4/IPv6/domain、空包、65,535 字节 payload、255 字节域名、拆粘包、metadata 长度/类型/ID、KeepAlive、End 的最后一包、错误标记、分配失败回滚、deadline、背压、取消后迟到 write 和 stop 屏障。
- `xudp_interop_contract`：固定 sing-box v1.12.12 与 Xray v26.10.31（`a4a3dff5b20c2faae567b742c172c7b95e75c083`）的 plain/TLS 双 worker、同族 A/B/A、IPv6、域名首包、备用回复端口和错误凭据/取消通过。Xray 另通过同一通道跨 IPv4/IPv6/domain。测试 Xray 只显式允许临时回环 UDP 目标，不改宿主网络设置。
- 两个固定外部对端均不返回空 XUDP；sing-box 还在同一通道从 IPv4 转 IPv6 时结束该 session。独立 sing-vmess v0.2.7 客户端在同一 peer 先验证正常回包再复现限制；支持空包的独立 Python VLESS/XUDP/TLS 对端通过真实 UDP echo 验证 Solaris 的完整空包与多目标路径。
- 共用 `tests/contracts/flow/udp/proxy.c` 经配置→registry→工厂验证 SS 五种 cipher 的 native UDP/UoT、AnyTLS UoT、VLESS XUDP。覆盖两个固定 owner、worker 集合更换后不迁移、一个 plan/三个 family lanes、A/B/A、域名、空包、批量接纳前缀、快照、配置提前释放、显式 association 取消及 executor stop 排空。XUDP 还覆盖异常/截断/End 对 association 的故障传播与已接纳回调排空。
- 本机共享/静态构建各完整 24 项检查及安装消费通过；XUDP/流式 datagram/VLESS TCP 的 ASan/UBSan、TSan 通过，三组代理互通与 association 的 sanitizer 检查也通过。测试以 owner fence 等待回调返回后读取快照；该版本已重跑静态及两种 sanitizer 的三组代理互通。全出站/TLS 关闭的静态裁剪构建 13 项通过。
- 一次 Xray 首包请求在正常对照成功后超时，尚未归因；随后同组 12 轮连续通过。此时未归因；后续复核见下方最终验收记录，不把单纯重跑通过当成原因证明。未运行远端 CI、设备或性能验收。

### VLESS encryption 验证（2026-11-05）

- 支持参数、资源上限和恢复语义见 [M1 数据路径](M1_DATA_PATH.md#vless-encryption)。VLESS 的配置→registry→工厂接入独立 encryption filter；TLS 与 encryption 可组合，UDP 仍走共享 XUDP/association。
- 固定 Xray v26.10.31 的 native/xorpub/random、X25519/ML-KEM/混合 relay、1-RTT/0-RTT、多轮连接、TLS、双 worker/双栈/domain、错误 UUID/服务端密钥、取消及 XUDP/association 通过。独立 Go fixture 确认真实恢复握手、恢复请求重放拒绝、两种 AEAD、握手/记录认证与 nonce 回绕换钥；另验证缓存过期、同代失败清理、旧代失败隔离、分片/截断与分配失败回滚。
- `stream_filter_contract` 验证握手 ready gate、响应先于最后一次 preface write 完成、padding 延时、读暂停、绝对 deadline、取消及 stop 等待迟到回调。共享构建 27 项分组验证、静态完整 27 项和安装消费通过。ASan/UBSan、TSan 的新增三组测试通过；最后补充未确认恢复关闭清理后，静态全套及共享 codec 重新通过。
- 默认 Xray 构建改用同一提交对应的 Go pseudo-version，独立执行默认 `go install` 路径并核对版本/完整提交成功。日志为 `build-m0-bootstrap/m1-encryption-*.log`。未提交/推送或运行远端 CI；Vision/raw 切换、M1-07/M1-08 仍未完成。

### Vision/raw 与 M1-07 验证（2026-11-05）

- Vision/raw 后共享与静态完整 30 项通过；raw/filter、Vision codec/互通、encryption codec、SS codec 的 ASan/UBSan 与 TSan 通过。负向配置测试复现并修复 VLESS/SS 对空 compile payload 的清理崩溃，未知/缺失字段回归通过。
- `select_contract` 验证跨 worker 共享选择、固定 leaf/修订、旧 plan/组退休和健康 token；`observation_contract` 验证准确计数、活跃/历史上限、并发查询、跨线程关闭、队列满、迟到完成、取消与资源失败；`probe_contract` 验证 URL/header、完整响应与写完成、绝对 deadline、取消与失败回收。各现有代理 TCP/UDP/association 套件均经过观测层，`proxy_probe_contract` 经独立 HTTP(S) 对端覆盖所有现有出站。
- M1-07 的 ASan/UBSan 9 组通过；TSan 的一次测试发布时序错误已修正（stop 可以在第二次 write 前关闭 admission），相关 observation/probe 重新通过，其余 8 组通过。全出站/TLS 关闭的静态裁剪 17 项通过。日志为 `build-m0-bootstrap/m1-observe-*.log`。
- `SOLARIS_BUILD_FUZZERS` 使用独立插桩 core；244 份协议/独立密码样本启动的 61 秒运行完成 1,077,892 次输入，覆盖边由 3,592 增至 4,014，无 ASan/UBSan 或预算断言错误。日志为 `build-m0-bootstrap/m1-fuzz-run.log`，并已加入 CI fuzz job；远端 CI 尚未运行。
- 仅 VLESS 裁剪首次运行中出现一次 encryption association 超时，未归因。随后 80 次带跟踪 association、80 组完整前置后的 UDP/association、400 组无跟踪 UDP/association，以及独立 Go 客户端四种承载各 100 轮双 worker 对照均通过。这属于当时的复查记录；最终验收补充了端口碰撞复现和独立控制端异常证据，见下文。

### M1 最终本机验收（2026-11-05）

M1-01–M1-08 已实现，G-BUILD/G-MODULE/G-LIFE/G-WORKER 及本阶段 G-UDP/G-INTEROP 的功能范围通过本机验收。
这是内部框架和声明组合的功能验收；不包含 M2 公开业务入口、远端 CI、真机或长时间生产稳定性结论。

- BoringSSL 固定为 0.20261020.0，锁定 tag/commit/归档与源码树哈希；干净复制、顺序补丁及结果树校验接入 CMake。
  Hello 认证/X25519 基础补丁已实现，真实 TLS transcript、PSK binder/恢复、错误身份、HRR/时序拒绝和补丁完整性检查通过。
  REALITY、ShadowTLS、Restls、JLS 的完整接入仍按 [TLS 设计](TLS_BACKEND.md) 推进；不把 hook 计为协议支持。
- SOCKS5 经 registry/factory 接入，无认证/用户名密码、TCP/UDP、双 worker、IPv4/IPv6/domain、wildcard/domain relay、
  备用源端口、异常报文丢弃、控制连接故障、整体 deadline、DNS 取消、真实 close 屏障与分配失败检查通过。
  select/固定 plan、测速、观测和 association 复用原有入口，未向通用层添加 SOCKS5 特判。
- 最终检查额外复现了通用 executor 停止顺序缺陷：关闭 admission 后，排队 TLS pump 在 scope 取消前运行，错误返回 ECLOSED。
  现先按原有有界批次发布 scope 取消，再推进 deferred 工作。确定性复现改为 ECANCELLED，192 scope 排空和全部生命周期检查继续通过。
  这是通用停止语义修复，与协议扩展没有耦合。

| 本机配置 | 结果 | 日志 |
| --- | --- | --- |
| Debug 共享 | 全部 40 项通过，含所有协议组合、私有符号、导出与安装消费 | `build-m0-bootstrap/m1-final2-shared-test.log` |
| Debug 静态 | 全部 40 项通过，含搬迁后的纯 C/C++ 消费 | `build-m0-bootstrap/m1-final2-static-test.log` |
| ASan/UBSan | 全部 40 项通过；BoringSSL ssl 层也插桩，crypto/libuv 内部未插桩 | `build-m0-bootstrap/m1-final2-asan-test.log` |
| TSan | 全部 40 项通过，无 race 忽略；同样包含 ssl 层插桩 | `build-m0-bootstrap/m1-final2-tsan-test.log` |
| 仅 Direct / 仅 Block / 全关闭 | 分别 18 / 17 / 17 项通过 | `build-m0-bootstrap/m1-final3-*-only-test.log`、`m1-final3-no-outbounds-test.log` |
| 仅 SOCKS5、关闭 TLS/crypto | 全部 21 项通过 | `build-m0-bootstrap/m1-final3-socks5-only-test.log` |
| 仅 TLS、从锁定 URL 全新下载 | 全部 22 项通过；宿主 Clang 23.1.4，主矩阵使用 AppleClang 21 | `build-m0-bootstrap/m1-final3-tls-only-test.log` |
| Parser fuzz | 19 个入口、270 份独立种子，61 秒 781,968 次输入，峰值 RSS 504 MiB；无 sanitizer/预算错误 | `build-m0-bootstrap/m1-final-fuzz-run.log` |

fuzz RSS 是 fuzz 进程的观测值，不是内核生产内存或吞吐结论。

重复互通的证据与限制：

- 复现了 macOS 双栈 UDP 临时端口与 IPv4 回显端口重合，回复被送回回显服务自身。独立 socket 程序在 389 次绑定时复现；
  测试目标改为同时预留两种地址族，同端口自回环立即报错。64 个预留端口的 10,000 次双栈临时绑定无重合。
  固定 sing-box/Xray 的 plain XUDP 扩展重复 250 轮通过，含 Xray 混合地址族及双 worker。
- Shadowsocks 的全局“唯一源端口数”断言把不同已关闭测试的端口复用误判为失败，现按同一次测试的两条活动通道验证 A/B/A，
  不再要求 OS 永不重新分配旧端口；内容完整性和同连接复用检查保留。
- 守护测试端口后，长重复 Xray encryption/XUDP 仍出现偶发无回复。**仅独立 Go 客户端运行时也复现了相同批量或额外 lane 超时**。
  Solaris 诊断显示缺失回复的 TCP 保持读取、各层输入为空且无待写/暂停数据；目标端收到并发送了对应数据报。
  这不是已定位并修复的 Solaris codec 缺陷，尚不能进一步断定是 Xray、内核还是本机网络环境的具体原因。
  常规互通已通过，长重复稳定性保留为外部对端/环境限制；库没有增加重试、伪造回复或改写目的地址掩盖。
  证据为 `m1-xudp-port-collision.txt`、`m1-encryption-peer-boundary.txt` 及其中引用的原始日志。

以上记录是提交前的本机验证；不包含 M1 远端 CI、系统 VPN、其他 OS 本机或性能测量证据。构建产物清理后，表中的本机日志、下载的参考源码和临时诊断文件不随源码保留；验证入口保留在 tests/ 和 scripts/ 中，可按测试规范重新运行。

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
| M5-02 | M5 | WS/gRPC/HTTP Upgrade/XHTTP，REALITY/ShadowTLS/Restls/JLS 与额外安全/指纹组合；按 TLS 补丁设计和独立对端逐项验收 |
| M5-03 | M5 | Windows/Linux/OpenHarmony 宿主接口、绑定与产物；各平台独立构建和设备验收 |
| M5-04 | M5 | 其他 mihomo 协议需求进入独立模块任务，包括 Snell/SSR/WireGuard/Naive 等需要专门后端的能力；先记录依赖与支持边界 |
| M6-01 | M6 | QUIC backend、Hysteria2/TUIC/DoQ/HTTP3 等按实际需求顺序接入，不能绕过 socket/protect 服务 |
| M6-02 | M6 | 额外链式代理、更多高级规则与协议组合；不突破公共依赖边界 |
| M6-03 | M6 | 串行栈瓶颈测量、可隔离/分片栈后端验证及 worker 分配优化 |
| M6-04 | M6 | 1/2/4 workers、普通/批量 I/O、单流/多流/Mux 性能测量；以数据确定默认值与预算 |

以上是覆盖路线，不是“阶段结束即全量支持所有 mihomo 版本”的声明。未排定或尚无独立互通证据的协议继续保留在兼容矩阵的未支持/未验证项。

## 9. 第一批可执行工作

M0 已推送并通过 CI；M1-01–M1-08 的实现与本机功能验收已完成。下一阶段从 M2-01 的 YAML 配置编译与诊断开始；远端 CI 和已知参考端/环境限制独立跟进。

继续沿用 registry、公共 I/O/scope 契约和受控对端验证；association 与代理协议必须有自身的数据路径和错误路径证据，不批量接回历史框架。

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
