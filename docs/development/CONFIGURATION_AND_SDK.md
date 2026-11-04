# 配置兼容与宿主 SDK

状态：当前开发规范；具体 API 声明尚待实现，进度见 [开发计划](DEVELOPMENT_PLAN.md)。

## 1. 兼容范围

公开输入是 mihomo YAML 与相应 provider payload。对照基准固定为 Herta-Network/mihomo `9f121787bb563fe655d2789cbf6dbcc7ae19a0c9`，即本次核对的 libclash 依赖；升级基准必须更新样本和差异记录。

不兼容原 Solaris 私有配置格式、旧函数表或旧 ABI；也不要求复制 libclash 的函数名、JSON 返回结构或 HTTP 控制 API。协议互通按独立对端与明确的协议组合验收。

每项兼容能力需要记录字段/默认值、行为、平台条件、测试 ID、支持状态和与基准的偏差。阶段性通过一部分配置不能标成“完整 mihomo 兼容”。

| 范围 | 首个目标阶段 | 核对重点 |
| --- | --- | --- |
| YAML 公共语法与 `proxies` | M2 | 锚点、别名、merge、标量转换、重复 key、名称与引用 |
| `mode`、基础 `rules`、`proxy-groups.select` | M2 | rule/global/direct、首匹配、UDP 能力过滤、选择固定 |
| HTTP/SOCKS/mixed 监听配置 | M2 | 多入站、认证、宿主覆盖、实际绑定结果 |
| `dns`、`hosts`、`tun`、`sniffer` | M3 | 上游策略、Fake-IP、双栈、网络变化、真实 backend 能力 |
| `proxy-providers`、`rule-providers`、`profile` | M4 | 原子更新、过滤、缓存、选择与 Fake-IP 持久化 |
| url-test/fallback/load-balance、Geo/RULE-SET | M4 | 健康状态、嵌套策略、语义顺序和文件格式 |
| 额外协议、传输、指纹及链式能力 | M5/M6 | 每个协议 × 传输 × 安全 × UDP 组合独立验收 |

M1 中模块可使用测试构造的配置视图，不代表完整 YAML 已支持。原代码中的 SS、VLESS、AnyTLS、REALITY、Vision、ECH、XHTTP 等实现也需要在新入口重新接通并验证。

## 2. 配置流水线

`YAML → 带源位置的节点 → 公共字段与默认值归一化 → 模块配置编译 → 引用/能力校验 → 资源准备 → 不可变快照 → 提交`

输入同时支持字节缓冲和文件路径；字节入口显式指定 base directory，供相对的 provider、证书与 Geo 路径解析。语法/静态语义校验不联网，资源准备与激活通过独立操作表达。

必须明确：

- 有配置大小、层数、节点数与别名展开上限，诊断包含字段路径与源位置。
- 未实现且影响转发的协议/字段/组合返回明确错误，不能静默改成 Direct。
- 模板用扩展节点按参考行为处理，不能简单拒绝全部未知顶层 key；模块报告消费过的字段。
- `external-controller`、`external-ui`、`secret` 等可解析并报告库模式不执行，不因此创建控制端口。
- 宿主对工作目录、监听和 TUN 参数的覆盖显式声明，报告请求值、覆盖值和生效值。
- `tun.stack` 必须对应实际 backend 能力；lwIP 不能冒充 system/gvisor/mixed。选择其他 backend 需要显式覆盖与诊断。
- 分享链接导入与 App 主订阅管理是独立输入功能，不让各平台分别重写核心 YAML 语义。

## 3. 路由、策略和 DNS

路由先实现可读、可测试的顺序解释器，再增加索引。优化不能改变首个有效匹配、延迟 DNS、`no-resolve`、UDP 能力过滤、逻辑规则和规则集顺序。

metadata 区分原始目的地址、域名、嗅探域名、解析结果、Fake-IP 关系与实际目标，包含网络类型、入站身份和可选进程/UID。修改 metadata 的阶段与效果必须可追踪。

策略组与节点共享 outbound 接口，组引用与 dialer-proxy 引用检测循环。selector、健康检查和负载均衡具有明确的全局/worker 状态归属，规则和 Provider 更新不隐式断开旧连接。UDP 的选路固定在 association 层，见 [UDP/NAT](UDP_NAT.md)。

DNS 是 TUN 与路由共用服务，覆盖报文解析、UDP/TCP 上游、hosts/cache、policy、DoH/DoT、Fake-IP、fallback 和独立的代理服务器域名解析路径；DoQ/HTTP3 随 QUIC 后端交付。

系统 DNS 更新按解析器代际失效相关缓存，不清除仍被关联使用的 Fake-IP 租约。上游 DNS、代理服务器解析与经代理拨号要检测依赖环，并应用宿主网络策略。

Provider 调度、内容编译和资源获取分层。下载候选内容，校验后原子发布，失败保留已生效快照；普通 HTTP(S)/文件后端与宿主特殊 URI 后端均可实现资源接口。rule-provider 的 classical/domain/ipcidr 与 yaml/text/mrs 支持状态分别登记。

## 4. 宿主 API 能力

普通 C 函数与 opaque handle 构成公开 SDK，不要求 get-api 版本协商、历史后缀或兼容保留槽。以下为能力分组，不是已存在的导出符号表：

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

TUN fd 默认由宿主拥有、库借用。若另设所有权转移接口，须说明成功与失败时谁关闭。protect 完成前不得 connect/首次发送，取消与迟到完成要防止 fd 已关闭复用后被错误保护。

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

参考：[libclash C 入口](https://github.com/Herta-Network/libclash/blob/main/cmd/main.go)、[固定 mihomo 配置模型](https://github.com/Herta-Network/mihomo/blob/9f121787bb563fe655d2789cbf6dbcc7ae19a0c9/config/config.go)。具体调查保存在 [历史总体草案](../archive/2026-11-03/MIHOMO_LIBRARY_DESIGN.md)。
