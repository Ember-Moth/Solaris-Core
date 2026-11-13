# 原生配置与宿主 SDK

状态：2026-11-13 更新的目标规范。Solaris Core 采用独立内核定位，原生配置定为 Surge 风格的 `.conf`；
当前源码仍有 YAML 入口，原生解析器与宿主切换按 [CFG 计划](DEVELOPMENT_PLAN.md#21-原生配置迁移与近期优先级) 实施。
具体可调用接口见 [当前 SDK](SDK.md)，本页的新设计不表示已可运行。

## 1. 原生配置与范围

格式名称为 **Solaris Conf v1**。借鉴 Surge 的 INI-like 分节及逐行声明，字段含义、默认值、策略和错误处理由 Solaris 自身规范决定。
不承诺完整 Surge 或 mihomo 配置可直接加载，也不复制其控制 API、管理配置、脚本或全部功能。
Surge 的格式仅作书写方式参考：[Profile Format](https://manual.nssurge.com/profile/format.html)。

### 1.1 v1 规范任务

以下作为 CFG-01 的规范基线，CFG-02 实现后才能声明支持：

- UTF-8 文本，允许文件开头的 UTF-8 BOM，支持 LF/CRLF；首版不支持隐式续行、多行值或宏展开。
- 每个段最多声明一次；段名和字段名使用规范中的固定拼写。节点/组名支持 UTF-8，区分大小写；trim 规则与引号保留范围明确。
- `[General]` 中显式填写 `config-version = 1`；未知版本、未知段/键、重复键/名称和无效引用报错，不静默忽略。
- `key = value` 在引号外的首个等号处分隔；逗号列表只在引号外切分；参数值中的后续等号按字段内容保留。
- 双引号包裹值，定义 `\"` 与 `\\` 转义；未知转义、未闭合引号和不完整参数报错。密码/URL/含逗号名称必须无损保留。
- 支持 `#`、`;`、`//` 注释；行内分隔符必须在引号外且前有空白，不能截断 `https://`、带片段的 URL 或引号内凭据。
- 字段 schema 决定值类型；布尔值采用 true/false，数值为十进制，时间/容量单位由字段规范声明。缺省、空值和零值分别定义。
- `[Rule]` 保持文件顺序。规则模式要求唯一、位于最后的 `FINAL`；未匹配动作显式填写，不由第三方默认行为补齐。
- 规则/参数只接受已经声明的能力；`#!include` 等管理指令显式报不支持，不当普通注释吞掉。远程 include、脚本、MITM 和托管 profile 不属于 v1。

### 1.2 段与实施批次

| 段 | 职责 | 首批范围 |
| --- | --- | --- |
| `[General]` | 版本、基本运行配置和默认监听 | CFG：仅保留宿主实际需要且能生效的设置，不把所有开关堆在全局段 |
| `[Proxy]` | `名称 = 协议, 地址, 端口, 参数...` | CFG：接已有 Direct/Reject/SOCKS5/SS/VLESS/AnyTLS 的已验证组合 |
| `[Proxy Group]` | 命名策略与成员引用 | CFG：手动 select；自动策略和组嵌套按实际需求进入 M4 |
| `[Rule]` | 有序匹配与明确最终动作 | CFG：已有基础 matcher 与 FINAL；引用/循环/能力检查统一 |
| `[Host]` | 静态地址与别名 | M3：定义自身匹配、别名、优先级及系统快照的边界 |
| `[DNS]` | resolver、上游、缓存和策略 | M3：按角色与真实实现逐项开放，不继承外部隐式服务器/回退 |
| `[TUN]` | 实际 backend 与宿主接入需求 | M3：明确设备能力、packet/FD、MTU、地址族和变更计划；不自动取得系统权限 |

`[DNS]`、`[TUN]` 等是 Solaris 的原生组织方式，段名不构成对 Surge 同名功能的兼容承诺。
段内详细字段、端口禁用/临时绑定、时间默认值及名称引用表在 CFG-01 冻结；未实现的段不能提前被解析成成功但无行为的配置。

下面是用于冻结规范的目标样例，**尚不是当前解析器可执行的配置文件**：

```ini
[General]
config-version = 1
http-listen = 127.0.0.1:7890
socks-listen = 127.0.0.1:7891

[Proxy]
Node = ss, proxy.example.com, 443, encrypt-method=aes-128-gcm, password="example-password", udp-relay=true

[Proxy Group]
Exit = select, Node, DIRECT

[Rule]
DOMAIN-SUFFIX,example.com,Exit
FINAL,DIRECT
```

## 2. 配置流水线与迁移

`Solaris Conf → lexer/parser 与源位置 AST → schema/名称/引用/能力校验 → owned 类型化配置 → prepare → commit → retire`

C SDK 消费同一个配置模型，配置文件不是运行时的数据结构；后续若提供直接类型化构建入口，必须复用同一语义校验与默认值。
文件/字节输入保留明确的 source/base-directory，错误包含段、键/条目和行列；错误信息与日志不输出密码、私钥或 token 原文。
输入字节、行长、token、条目、嵌套引用及诊断数量分别限额；语法和静态检查不联网、不读外部资源、不绑定监听或创建设备。

- 原生编译器直接构建公共模型，不先转换成 mihomo YAML 再调用旧解析器，不把第三方 schema 固化成内部标准。
- 新默认入口与旧 YAML 入口必须明确区分，不能在 `.conf` 失败后隐式尝试 YAML；CFG-03 冻结 API/调用约定并迁移安装样例。
- 现有 YAML 实现暂留以维持迁移期间的构建和回归。CFG-04 完成后，按实际引用将其及专属参考工具/依赖移出默认库与默认门禁；不新增长期双格式维护义务。
- 旧格式导入若有明确需求，作为独立外围适配器输出公共模型；当前迁移不额外交付转换器。
- 宿主对监听、TUN 和网络能力的覆盖显式声明，结果包含请求、覆盖与生效值；不可用功能返回明确错误，不自动改为 Direct 或其他 backend。
- 配置格式变化不改变连接所有权、取消屏障或已建立流的路由；改变这些行为须单独设计和回归。

## 3. 路由、策略和 DNS

路由先实现可读、可测试的顺序解释器，再增加索引。优化不能改变首个有效匹配、延迟 DNS、`no-resolve`、UDP 能力过滤、逻辑规则和规则集顺序。

metadata 区分原始目的地址、域名、嗅探域名、解析结果、Fake-IP 关系与实际目标，包含网络类型、入站身份和可选进程/UID。修改 metadata 的阶段与效果必须可追踪。

策略组与节点共享 outbound 接口，组引用与 dialer-proxy 引用检测循环。selector、健康检查和负载均衡具有明确的全局/worker 状态归属，规则和 Provider 更新不隐式断开旧连接。UDP 的选路固定在 association 层，见 [UDP/NAT](UDP_NAT.md)。

DNS 是 TUN 与路由共用服务，覆盖报文解析、UDP/TCP 上游、hosts/cache、policy、DoH/DoT、Fake-IP、fallback 和独立的代理服务器域名解析路径；DoQ/HTTP3 随 QUIC 后端交付。

系统 DNS 更新按解析器代际失效相关缓存，不清除仍被关联使用的 Fake-IP 租约。上游 DNS、代理服务器解析与经代理拨号要检测依赖环，并应用宿主网络策略。

资源调度、内容编译和获取分层。下载候选内容，校验后原子发布，失败保留已生效快照；HTTP(S)/文件及宿主资源接口按实际需求接入。
原生节点/规则资源有独立格式与版本；第三方资源格式只在明确需要时提供外围适配器，不以其格式清单约束核心模型。

## 4. 宿主 API 能力

普通 C 函数与 opaque handle 构成公开 SDK。以下为目标能力分组；已实现的导出和生命周期约定以 [SDK](SDK.md) 为准：

| 分组 | 操作 |
| --- | --- |
| 生命周期 | 创建、准备/应用配置、启动、停止、销毁、状态 |
| 配置 | 字节/文件输入、校验诊断、有效配置与宿主覆盖报告 |
| 控制 | 切换 rule/global/direct、枚举策略组、选择节点 |
| 健康检查 | 可取消测速、组健康检查、结果与历史 |
| Provider | 枚举、刷新、进度、错误和当前快照 |
| 观测 | uint64 上下行字节、速率、内存、连接快照和日志/事件 |
| 连接 | 按 ID 或全部关闭，定义 TCP 与 UDP association 的边界 |
| 平台 | TUN 接入、socket protect、网络/DNS 变化、可选 UID/进程信息 |
| 资源 | 预算、空闲缓存回收、宿主资源读取与信任材料 |

SDK 不沿用 packed traffic 或进程全局 last-error。错误必须能关联到 engine/operation，查询结果使用受控生命周期的快照，跨库分配通过库的释放函数回收。JSON 可以作为绑定的便利输出，不成为所有调用的唯一编码。

## 5. 生命周期与所有权

1. 宿主创建 engine，提供回调、目录、worker 数与预算等运行选项。
2. 编译配置并查看诊断，准备资源与平台变更计划。
3. 宿主建立系统 VPN/TUN；按配置计划完成库激活。
4. 控制操作进入 owner 命令队列，通过 operation ID 返回结果。
5. 停止 packet admission，停止 engine 并等待异步任务与回调屏障，再释放宿主 TUN/回调上下文。
6. destroy 回收 engine 和线程，不允许在会等待自身的内核回调线程执行阻塞销毁。

输入在 API 返回前复制，或通过独立 owned-handle 接口明确转移所有权；借用输出只在约定回调范围有效。成功接纳的异步操作只有一次最终结果，取消不能让迟到回调访问已释放对象。

TUN fd 的原始句柄由宿主拥有；已有 FD 接入由库复制并只关闭副本，具体约定见 [TUN](TUN.md)。若另设所有权转移接口，须说明成功与失败时谁关闭。protect 完成前不得 connect/首次发送，取消与迟到完成要防止 fd 已关闭复用后被错误保护。

packet callback 与控制事件独立管理线程和容量；库回调不假定宿主 UI 线程，也不允许慢 UI 造成无界内存积压。

## 6. 事务式配置更新

采用 `prepare → commit → retire`。候选配置和可准备资源校验失败时保持原运行状态；提交后新连接/association 使用新快照，旧对象持有原快照直到结束。

主配置、Provider 与选择状态各有自己的 revision；Provider 刷新不重启整个 TUN。端口重绑定、TUN 参数和系统路由等资源单独形成变更计划，报告可在线应用或需要宿主重建，不承诺所有字段都无损切换。

## 7. 平台边界

| 平台 | 宿主拥有 | 库提供 |
| --- | --- | --- |
| Android | VpnService、VPN 权限、系统 TUN、protect、网络与 UID 信息 | `libsolaris.so`、C SDK、JNI/AAR 或 P/Invoke 薄绑定 |
| iOS/macOS | Network Extension、NEPacketTunnelFlow、VPN 生命周期 | `Solaris.xcframework`、module map/Swift 包装、packet callback |
| Windows | Wintun、路由、DNS、物理接口与权限 | `solaris.dll`、header/import library、packet callback |
| Linux | 系统 TUN、路由策略与权限 | 共享/静态库、fd 或 packet callback |
| OpenHarmony | VPN Extension、TUN、保护与宿主事件循环 | `libsolaris.so`、C SDK、N-API/宿主薄绑定 |

证书信任、网络变化、进程查询和资源路径是明确的平台能力；不能假定所有平台共享同一系统证书路径或进程 API。实际平台能力与构建产物分别验证。

早期 mihomo/libclash 调查保存在 [历史总体草案](../archive/2026-11-03/MIHOMO_LIBRARY_DESIGN.md)，作为技术资料，不定义 Solaris 原生配置或当前完成条件。
