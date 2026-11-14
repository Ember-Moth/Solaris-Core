# 原生配置与宿主 SDK

Solaris Conf v1 是当前字节/文件入口的原生格式。下面第 1–2 节定义已实现的语法、字段和编译边界；
第 3–7 节同时保留后续 DNS/TUN/平台能力的设计方向，具体状态见 [开发计划](DEVELOPMENT_PLAN.md)。
公开调用和生命周期约定见 [SDK](SDK.md)。

## 1. Solaris Conf v1

采用 INI-like 分节和逐行声明，借鉴 Surge 的[书写形式](https://manual.nssurge.com/profile/format.html)。
语义由 Solaris 定义，不承诺 Surge 或 mihomo 文件兼容。文件扩展名不参与格式探测；字节与文件入口均只接受本规范。

### 1.1 词法与诊断

- 输入必须为 UTF-8，允许文件开头的 BOM；接受 LF/CRLF，不接受单独 CR、NUL、其他控制字节或中间 BOM。列号从 1 开始，按 UTF-8 字节计数。
- 段名使用下表的精确拼写，每个段最多一次。段前允许空白，段标题内不加空白。字段与名称区分大小写；节点、组、监听和认证 profile 名称支持 UTF-8，长度为 1–127 字节。
- 行首/行尾未引用的空格与 tab 被 trim。双引号覆盖整个 token；只定义 `\"` 和 `\\` 转义，其他转义与拼接引号报错。引号内空白保留，`""` 表示显式空字符串。
- `名称 = 值` 在引号外第一个等号处分隔；列表在引号外的逗号处分隔；参数在引号外第一个等号处分隔。参数值中的后续等号属于内容。没有 YAML 隐式类型、anchors、merge 或变量展开。
- `#`、`;`、`//` 可在行首或引号外且前有空白处开始注释。`https://x/a#fragment` 不被截断；含空白加注释字符、逗号、引号的凭据必须引用。`#!include` 等 `#!` 指令明确返回不支持。
- 字段 schema 决定类型，引用不会改变类型：`true` 与 `"true"` 在布尔字段中都为 true；仅接受小写 true/false。无符号整数仅接受十进制数字，前导零仍按十进制；不接受正负号、下划线、十六进制或单位后缀。字符串中的 `00123`、`true`、`null` 均原样保留。
- 未知段/字段/能力返回 `SOLARIS_ENOTSUP`；语法、重复项、缺失字段、值或引用错误返回 `SOLARIS_EINVAL`；输入/结构限额返回 `SOLARIS_EOVERFLOW`；总内存预算或分配失败返回 `SOLARIS_ENOMEM`。
- 词法诊断使用 PARSE 阶段，字段/模型诊断使用 NORMALIZE 阶段；包含 source、段/条目/字段路径与行列。重复键另给出首次位置。诊断不包含凭据原文或未知字段原文。

### 1.2 段与入口

| 段 | 内容 | 支持状态 |
| --- | --- | --- |
| `[General]` | 版本、初始模式、三个快捷监听、默认认证 profile | 必须出现 |
| `[Proxy]` | 命名出站记录 | direct、reject、socks5、ss、vless、anytls；受构建裁剪约束 |
| `[Proxy Group]` | 命名手动选择组 | 平面 select，成员只能是出站节点 |
| `[Rule]` | 有序规则行 | 基础 matcher 与唯一且末尾的 FINAL |
| `[Listener]` | 命名 HTTP/SOCKS5/mixed 监听 | 多监听、UDP 开关、独立认证选择 |
| `[Authentication]` | 命名用户密码集合 | 可被 General/Listener 引用 |
| `[DNS]` | 现有内部 DNS 服务配置 | 数值 UDP/TCP 上游、解析角色、hosts/cache；详见 1.7 |
| `[Host]` | 数值地址集合或域名别名 | 双栈、多地址、别名与循环检测 |

`[TUN]`、远程 include、脚本、MITM、托管 profile、Provider 与未列出的段不被接受。
TUN 内部组件或加密 DNS 组件的存在不表示其原生配置入口已经交付。

### 1.3 General

| 字段 | 值与缺省 | 空值/零值 |
| --- | --- | --- |
| `config-version` | 必填，精确值 `1` | 其他值拒绝 |
| `mode` | `rule`（缺省）、`global`、`direct` | 空值拒绝 |
| `http-listen` / `socks-listen` / `mixed-listen` | 数字 `IPv4:port` 或 `[IPv6]:port`；缺省或 `off` 不创建对应监听 | port 仅 1–65535；0 拒绝 |
| `authentication` | `[Authentication]` 中的 profile 名称；缺省或 `""` 无认证 | 不接受不存在的 profile |

快捷监听的名称分别为 `http`、`socks`、`mixed`。HTTP 无 UDP；SOCKS5/mixed 默认启用 UDP。
快捷监听与命名监听共享名称/地址检查，重复名称或完全相同的已启用 endpoint 拒绝。
宿主需要临时端口时，在 prepare 中按已有 listener ID 显式覆盖为端口 0；这不会使 `off` 的监听出现。

rule 模式要求 `[Rule]`；direct/global 可以不带规则。没有规则的配置不能通过控制 API 切到 rule。
reload 保留当前模式：若提交时仍为 rule 而候选没有规则，提交失败并保留旧配置；不隐式重置模式或补入 Direct。

### 1.4 Proxy

```ini
[Proxy]
Local = direct, udp-relay=true
Blocked = reject
Node = ss, proxy.example.com, 443, encrypt-method=aes-128-gcm, password="example-password", udp-relay=true
```

远程协议的前三个位置依次为协议、地址、端口；direct/reject 只有协议位置。地址是数值 IP 或域名，端口 1–65535。
其余均为不重复的 `参数=值`。公共参数 `udp-relay` 控制配置的实际 UDP 能力：direct/reject 缺省 true，其他协议缺省 false。
远程协议可填 `network=tcp`，缺省或空字符串均使用 TCP；其他 carrier 返回不支持。direct/reject 只接受 udp-relay。
内置 `DIRECT`、`REJECT` 以及自动生成的 `GLOBAL` 是保留名称；节点与组共用名称空间。

| 协议 | 字段、单位和缺省 |
| --- | --- |
| socks5 | 可选 `username`、`password` 必须成对出现，各为 1–255 字节；无字段表示无认证 |
| ss | 必填 `encrypt-method`、`password`；支持现有 AEAD/2022 密钥校验。`udp-over-tcp` 缺省 false；启用时必须显式 `udp-over-tcp-version=2`，无 v1 |
| vless | 必填 `uuid`，32 位十六进制或标准带连字符格式。`tls` 缺省 false，`encryption` 缺省/`none` 为无协议加密。`flow` 缺省/空为基础 VLESS，可用 `xtls-rprx-vision` 或 `xtls-rprx-vision-udp443`，必须有 TLS 或 VLESS encryption。`tls-server-name` 只在 TLS 开启时接受；`packet-encoding` 缺省或 `xudp` |
| anytls | 必填 `password`，可选 `tls-server-name`，始终使用 TLS。`idle-session-timeout-ms` 与 `idle-session-check-interval-ms` 各缺省 30000，范围 1–3600000 毫秒；小值按原值生效，0 拒绝。`min-idle-session` 缺省 0，范围 0–64 |

密码与 SS 密钥文本上限 1024 字节，VLESS encryption 文本上限 16383 字节。
TLS 根证书由宿主 prepare 的 PEM 参数注入；配置不读取证书、私钥或系统信任，不接受关闭证书验证的开关。
协议组合和独立对端范围见 [能力矩阵](COMPATIBILITY.md)。

### 1.5 Proxy Group 与 Rule

```ini
[Proxy Group]
Exit = select, Node, DIRECT

[Rule]
DOMAIN-SUFFIX,example.com,Exit
IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
FINAL,REJECT
```

select 至少一个成员，初始选择第一个；重复成员、无效引用、组嵌套和循环拒绝。内置 GLOBAL 包含全部节点，初始选择 DIRECT。
规则保持文件顺序；普通行是 `类型,匹配值,目标[,no-resolve]`，FINAL 是 `FINAL,目标`。
只要声明 Rule，就必须有唯一且位于末尾的 FINAL；不接受 MATCH 别名。

支持 DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6、SRC-IP-CIDR、SRC-PORT、DST-PORT、NETWORK。
域名 matcher 使用 ASCII，按现有域名规范化处理大小写与尾点；目标可以是内置节点、自定义节点或组。
端口 matcher 接受 0–65535 单值或递增闭区间 `起点-终点`；NETWORK 接受 tcp/udp（也接受 TCP/UDP）。
`no-resolve` 只对 CIDR 规则可用；源地址 CIDR 本来就不触发目标解析。目的 IP 匹配最多触发一次延迟 DNS。

普通规则匹配的节点无 UDP 能力时继续下一条；FINAL 是终止动作，其所选节点无所需能力时返回 ENOTSUP，不能再隐式改走 Direct。
选路及控制状态在新连接/association 接纳时固定，已有流的生命周期不因文件格式变化而改变。

### 1.6 Listener 与 Authentication

```ini
[Authentication]
LocalUsers = alice="p,a=ss", bob="another password"

[Listener]
Web = http, 127.0.0.1, 7890, authentication=LocalUsers
Socks = socks5, ::1, 7891, udp-relay=true, authentication=LocalUsers
Public = mixed, 127.0.0.1, 7892, authentication=""
```

监听前三个位置为 `http/socks5/mixed,数字地址,端口`。与 Proxy 的端口一样仅 1–65535，地址不经过 DNS。
SOCKS5/mixed 可用 udp-relay，缺省 true；HTTP 上出现该字段即报不支持。
authentication 缺省继承 General；显式 `""` 禁用认证；填 profile 则替换继承集合。

Authentication 每个 profile 是逗号分隔的 `用户名=密码` 列表，至少一个用户；用户名与密码各为 1–255 字节。
同一集合内的重复用户名拒绝。用户名中的等号、逗号可以整体引用；冒号是普通字符，不用于切分凭据。
即使 profile 暂未被监听引用，其内容也进行完整校验。

### 1.7 DNS 与 Host

```ini
[DNS]
enabled = true
use-system-hosts = false
listen = 127.0.0.1:1053
upstream = udp://127.0.0.1:5353, tcp://[::1]:5353
proxy-upstream = 127.0.0.2
ipv6 = true
ipv6-wait-ms = 100

[Host]
api.example = 127.0.0.2, ::1
alias.example = api.example
```

DNS 的所有上游必须是数字 IP，裸地址默认 UDP/53；也接受 `udp://`、`tcp://` 与显式端口。
多个上游按顺序作传输故障切换。启用时必须显式设置 upstream，不内置公网 DNS，也不在该模式下回退系统查询。
`enabled=false` 且宿主未要求 strict DNS 时，运行时可以使用系统 resolver；strict DNS 要求宿主提供网络快照、保护回调与有效上游。
启用 DNS 且保留 `use-system-hosts=true` 时，prepare 要求显式宿主网络快照；没有该快照可设置 `use-system-hosts=false`。

| 字段 | 支持范围/缺省 |
| --- | --- |
| `enabled` / `ipv6` | false / false |
| `use-hosts` / `use-system-hosts` | true / true；系统 hosts 来自宿主快照 |
| `ipv6-wait-ms` | 100 毫秒，0–10000 |
| `upstream` | 客户端查询的上游列表，也是各角色的缺省值。每份列表最多 16 个数值端点 |
| `route-upstream` | 目的 IP 路由规则触发域名解析时使用的有序列表。省略时使用 upstream。Direct 可复用本次路由选中的数值地址 |
| `direct-upstream` / `proxy-upstream` / `bootstrap-upstream` | 独立角色列表；缺省使用显式 upstream 集合，不添加其他服务器 |
| `mode` | 缺省或 normal；Fake-IP 答复尚未接线 |
| `cache-algorithm` | 缺省或 lru |
| `cache-size` | 缺省/0 使用现有 4096 项上限，也可显式 4096；其他值暂不支持 |
| `listen` | 缺省、空字符串或 `off` 关闭监听。启用时填写数字 IPv4:port 或 [IPv6]:port，端口 1–65535，同时设置 `enabled=true` |

示例在 IPv4 回环端口 1053 上提供 UDP 和 TCP，并使用端口 5353 上的独立上游。宿主只需一条名为 `dns`、协议为 `SOLARIS_LISTENER_DNS` 的监听记录。使用该 ID 在 prepare 时覆盖为端口 0，两个传输会绑定同一临时端口。prepared 与 active 的监听快照均报告真实端点。DNS 监听使用客户端查询角色的 `upstream`，并遵循 `use-hosts`。

prepare 成对绑定两个 socket，commit 发布后接纳查询。任一绑定失败会回收候选的两个端点，旧配置继续服务。编译检查明确的上游自引用，prepare 再按宿主覆盖后的实际端点检查，通配监听会核对同端口的本机接口地址。同端点的 DNS 配置热更新复用物理监听。原有 TCP 连接和在途 UDP 请求沿用接纳时的配置，新连接和新数据报使用已发布的配置。`stop` 会关闭接纳并排空连接、查询回调与发送。

UDP 普通回复上限为 512 字节。带 EDNS 的回复受客户端通告值和 1232 字节服务上限约束，超出时设置 TC，客户端可用 TCP 获取完整答复。两跳分别协商 EDNS 大小。TCP 使用两字节长度前缀，允许分片、合并帧和按查询 ID 匹配的乱序回复。上游失败返回 SERVFAIL，格式无效的 UDP 查询丢弃，格式无效的 TCP 帧关闭对应连接。如果修改 OPT 会破坏未知记录中的压缩偏移，也返回 SERVFAIL。

每个监听代际最多 128 条 TCP 连接、256 个在途查询或回复，每条 TCP 连接最多 16 个流水请求。输入和回复的缓冲另受 8 MiB 上限及 engine 总预算约束。查询与未完成的 TCP 帧使用 5 秒期限，TCP 空闲 30 秒后回收。

Host 单值可以是数值地址或域名别名；多个值必须全部是无 scope 的数值地址，IPv4-mapped IPv6 会归一为 IPv4，地址顺序与重复项保留。
Host 名称为 ASCII，折叠大小写、去除一个尾点；每个 label 最多 63 字节，完整名称最多 253 字节。
从右向左逐 label 匹配时先精确分支，再整 label 的 `*`，再前导 `.`（一个或更多 label）；`+.` 同时声明基础名称和后缀。
不支持部分 label 通配、非 ASCII 或自动 IDNA。规范化后的重复模式（含 +. 展开重叠）与别名环拒绝。
配置命中后不会因为地址族或别名结果缺失再落到系统 hosts；配置未命中才查询宿主系统层。内置 localhost 为 127.0.0.1，可由配置覆盖。
别名在所属层内解析；外部终止别名保留为后续查询目标，编译时不联网。每项最多 16 个地址、别名最多 32 跳，配置与默认 hosts 合计最多 4096 项。
加密 DNS URI、nameserver-policy、Fake-IP 答复及 TUN 自动接线不在当前原生配置范围，组件测试不能替代这些能力的验收。

### 1.8 输入预算

通过 `solaris_config_options_init` 获取默认值；调用方填 0 使用默认。所有 AST、解码字符串、image 与诊断分配共享内存预算。

| 选项 | 缺省 | 可设置上限 |
| --- | --- | --- |
| input_limit_bytes | 1 MiB | 64 MiB |
| memory_limit_bytes | 16 MiB | 由宿主指定 |
| string_limit_bytes | 64 KiB | 64 MiB；单 token 的引用内容解码前字节数，协议字段另有较低上限 |
| line_limit_bytes | 64 KiB | 64 MiB；不含 LF/CRLF |
| node_limit | 65536 | 1048576；AST 节点总数 |
| entry_limit | 16384 | 1048576；非空、非注释的段/声明行数 |
| diagnostic_limit | 64 | 1024 |

首版没有递归语法、include、alias 或组嵌套，不保留旧 YAML 的 depth/alias 限额选项。
source_name 上限 511 字节，base_directory 上限 4095 字节；选项元数据无效时返回 EINVAL。

## 2. 配置流水线与宿主切换

`Solaris Conf → lexer/parser 与源位置 AST → 字段/名称/引用/能力校验 → owned 类型化配置 → prepare → commit → retire`

`src/config/conf/` 直接构建源位置 AST，`src/config/image/` 生成模块私有字段、规则、组和监听等 owned 模型。
没有先生成 YAML 的过程。运行时不读取文本 AST，也不依赖第三方 schema；未来类型化构建 API 必须复用同一语义校验。
当前 C SDK 通过 `solaris_config_compile_bytes/file` 使用这一编译器，函数名保留但输入格式已切换，旧 YAML 不再接受。

字节入口不访问网络、文件、证书、监听或设备；文件入口只读取显式指定的一份有界文件。source/base_directory 在返回前复制，
base_directory 仅作为来源元数据保留，当前字段不加载外部资源。image 与 diagnostics 有独立 retain/release；释放 AST 不影响输出。
错误文本不回显凭据，公开配置快照不含密码，内存回收清零编译 arena。

旧 YAML parser、libyaml 私有 shim 和构建依赖已移除；M2 的参考程序、Go locks、176 个差分样本与原依赖信息保存在
[历史测试目录](../../tests/archive/yaml/README.md)，不进入默认构建、CI、安装或 fuzz。历史通过记录不改写为原生配置证据。
原生格式失败后不会回退旧格式；本次不提供格式转换器或导入适配器。

宿主的监听覆盖继续报告 configured/requested/actual；配置更新继续复用现有资源所有权、取消屏障和旧流保活机制。

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
