# 能力、协议与平台支持矩阵

方向更新：2026-11-13。Solaris Core 按独立内核推进，原生配置目标是 Surge 风格 `.conf`；迁移按 [CFG 计划](DEVELOPMENT_PLAN.md#21-原生配置迁移与近期优先级) 实施，尚不能直接加载该新格式。
下表的已有实现与测试记录主要来自 M2 阶段；旧 YAML 支持范围继续说明当前入口，不再作为后续完整兼容目标。协议/平台能力仍按实际验证声明。

| 能力 | 当前状态 | 任务/验收 |
| --- | --- | --- |
| Solaris C 生命周期、操作事件、状态 snapshot、flush/destroy | 已实现；macOS arm64 本机验证 | M0-03 / G-LIFE |
| 共享/静态安装包与 `Solaris::core` | 已实现；macOS arm64 全模块共享/静态独立 C/C++ 与纯 C 消费，x86_64 基础共享包经 Rosetta 运行 | M0-04 / G-BUILD |
| 多个 engine 内 I/O workers | 已实现 1–32 配置，双 worker 本机验证 | M1-01 / G-WORKER |
| stream/datagram、buffer/scope、Direct/Block | 内部接口已实现，双栈受控对端验证 | M1-02/M1-04 / G-LIFE |
| 模块 registry/配置工厂 | 内部接口已实现；离线 YAML 可生成模块私有 view，双 worker 配置/plan 交接已验证；每 worker 运行时 bundle、宿主 trust 注入、失败整批回收与延后退休已接入 | M1-03 / M2-03 |
| 单 datagram 多目的复用、空包/真实 source | Direct socket 路径已验证 | M1-02/M1-04 / G-UDP 子项 |
| UDP association、目的映射/reply endpoint 服务 | 已实现；命名空间隔离、固定 worker/plan、双栈/域名、deadline/关闭本机验证；映射模式可查询 | M1-05 / G-UDP 基础子集 |
| DNAT/Fake-IP 回复恢复、公网 NAT/设备行为 | 尚未实现/验证，不从本地端口复用推导 | M3 / G-UDP/G-DEVICE |
| 中立 TLS、裸 VLESS TCP/plain 或 TLS | 内部配置工厂已接入；固定 sing-box v1.12.12 双 worker/双栈/域名互通；显式 CA 与 identity 校验；encryption/flow 组合分别见下表，YAML → SDK 的 plain/TLS 与 XUDP 基线已验证 | M1-06a/b / G-INTEROP 子项 |
| VLESS encryption | 已接入 `mlkem768x25519plus`，native/xorpub/random、1-RTT/0-RTT、X25519/ML-KEM 密钥及 relay 链；固定 Xray 的 TCP/XUDP/association 与独立 crypto fixture 本机通过 | M1-06c / G-INTEROP |
| VLESS `xtls-rprx-vision` | 已接入 padding、内层 TLS 1.3 识别和双向 raw 切换；固定 Xray 的 TLS 1.3、三种 encryption 外观及 encryption-over-TLS 组合通过；基础 flow 拒绝 UDP 443，后缀 `-udp443` 放行 | M1-06d / G-INTEROP |
| VLESS XUDP | Single XUDP 已接入 plain/TLS、共享 datagram backend 与 association；固定 sing-box/Xray 和独立线格式对端已验证；已实现稳定 GlobalID 的跨连接恢复，固定 Xray 验证 UDP 映射连续；不重放数据报 | M1-06e / G-UDP U06/G-INTEROP |
| SS AEAD/2022 TCP/native UDP | 三种 AEAD、两种 2022 AES 与 2022 ChaCha 已接入；AES EIH/多用户最多 8 层身份链，独立对端验证；插件仅预留中立注入接口，无插件实现 | M1-06f / G-INTEROP 子项 |
| SS UoT | 内部 `udp-over-tcp: true` 使用共享 UoT v2；YAML 编译另要求显式 `udp-over-tcp-version: 2`，避免将参考实现的默认 v1 误接为 v2；六种 cipher 的内部和 YAML → SDK 路径已互通，无 v1/connect 模式 | M1-06g / M2-01 / G-UDP U06 |
| AnyTLS/session/UoT | AnyTLS v1/v2 协商、TLS、padding 更新、session 空闲策略与共享 UoT 已接入；本机双 worker/双栈/域名互通；协议无半关闭 | M1-06g/h / G-INTEROP |
| SOCKS5 outbound 扩展试验 | 已实现 CONNECT/UDP ASSOCIATE、无认证或用户名密码、双栈/domain、控制连接生命周期、select/测速/观测；无 BIND、UDP 分片或 TLS 配置入口 | M1-08 / G-MODULE/G-INTEROP |
| Solaris Conf `.conf` | 规范与迁移已列入计划，原生 parser/默认入口/安装样例尚待切换 | CFG-01–04 / 原生 G-CONFIG |
| 旧 mihomo YAML 入口：公共语法/proxies/rules/mode/select | 已实现离线 bytes/file 编译、owned image/诊断、平面 select 和基础字段归一化；已通过公开 SDK prepare/commit 激活真实代理业务 | M2-01 / 176 个完整加载器差分样本，范围见下文 |
| 顺序规则与异步 route job | 内部已实现 10 类规则、rule/global/direct、一次惰性 DNS、UDP 能力过滤、固定 plan、取消/超时/stop；已接入 TCP/UDP 入站，首包固定配置并排空取消中的 DNS | M2-02a–e / M2-05b 已接通 |
| SOCKS5/HTTP/mixed 内部入站 | TCP、UDP ASSOCIATE、认证、多监听器、WebSocket Upgrade/CONNECT WS/WSS 和回环互通已实现；普通 HTTP 每连接单请求；已有 YAML/公开 SDK 激活与更新入口；[用法与限制](PROXY_INBOUND.md) | M2-04 内部路径已实现 / G-LIFE/G-UDP |
| 配置与控制 SDK | 离线编译、prepare/commit、模式/节点选择、owned 节点组/连接快照、连接关闭、流量、可取消测速与有界日志已公开；取消、乱序完成与回调屏障已实现 | M2-05a–d 已接通 |
| prepare/commit/retire 配置事务 | 运行时 bundle、全局 revision CAS、物理监听复用/端口交换、失败回滚及旧连接/UDP lane 保活已接通；显式 stop 清空并排空全部代际 | M2-06 主配置/监听路径；完整配置差分与 M2-07 证据见开发计划 |
| 最小系统域名解析 | TCP 与 UDP association 使用 getaddrinfo；底层 Direct UDP send 仍只接收数值地址 | M1-04/M1-05 |
| DNS policy/DoH/DoT/Fake-IP | 尚未实现 | M3-01–M3-03 / G-UDP |
| 双栈 TUN 内部入站 | lwIP/system TCP、UDP association、宿主 packet/FD、Apple/Linux native 与 Wintun backend 已实现；合成 IP、回环 socket、模拟 ring 验证，真实系统路由/驱动未验收；[限制与用法](TUN.md) | M3-04 部分提前实现 / G-LIFE/G-UDP |
| Android/Apple 系统 VPN 与薄绑定 | 尚未实现/真机未验证 | M3-05–M3-06 / G-DEVICE |
| Provider、健康策略、Geo/RULE-SET、持久化 | 尚未实现 | M4 / G-CONFIG/G-RELOAD |
| 内部 select/固定 plan | 共享选择修订、worker 实例、存量 plan 固定；公开 mode/select 使用配置 revision 检查；reload 在提交点迁移最新仍有效选择，快照提供重置原因 | M1-07 / M2-01 / G-WORKER |
| 连接追踪与流量 | 接纳/握手/待路由/flow/association 记录、有界历史、公开按 ID/当前集合关闭并等待排空；USER/PROBE 逻辑分桶与独立物理 socket 汇总 | M1-07 / M2-05c / G-LIFE |
| HTTP(S) 单次测速 | 公开节点/组目标的 HEAD 请求，完整响应头与写入完成才成功；复制输入、显式 HTTPS 信任/身份验证、整体 deadline、取消与完整回收 | M1-07 / M2-05d / G-INTEROP |
| REALITY/ShadowTLS/Restls/JLS/ECH/XHTTP/指纹等额外组合 | 生产出站/配置尚未接入；[五个 TLS 库补丁](TLS_BACKEND.md) 已实现，四种认证握手经独立对端验证；Vision 已在 M1-06d 验证 | M2-03/M5-02 / G-INTEROP |
| Windows/Linux/OpenHarmony | M0 Windows/Linux CI 已通过；本批 Windows MinGW 32/64 位基础库与 C 宿主交叉链接通过，x64 DLL 仅导出 56 个公开 API；本批无 Windows/Linux 原生运行或远端 CI | M0-05/M5-03 / G-BUILD/G-DEVICE |
| QUIC/Hysteria2/TUIC/DoQ/HTTP3 | 尚未实现 | M6-01 / G-INTEROP |
| 多核吞吐、尾延迟、能耗改善 | 未测量 | M6-03–M6-04 / G-PERF |

当前实现不接受旧项目的原 schema，也不提供 mihomo HTTP 控制器。原协议代码/探针保存在 Git 历史和文档归档中，其通过记录不计为新实现的支持状态。

## M2 离线编译边界

以下描述已有 YAML 入口及原交付范围；不是 Solaris Conf 的字段表。原生规则见 [配置规范](CONFIGURATION_AND_SDK.md)。

顶层支持 `mode/proxies/proxy-groups/rules/port/socks-port/mixed-port/allow-lan/bind-address/authentication/listeners`。
支持 anchors、alias、map/sequence merge，显式字段覆盖 merge，merge 序列前项优先；重复 key、循环 alias、非字符串 key 和多文档拒绝。
controller/UI/secret 字段报告库模式不执行；有 anchor 的模板及 `x-` 扩展可以承载模板，未知转发设置仍拒绝。
保留 YAML map 标量类型再按字段转换，避免将 `_123`、`yes` 等字符串凭据改写；弱字符串字段不接受浮点或 bool，使用引号表达字面凭据。

| 字段/组合 | 当前编译行为 |
| --- | --- |
| `name/type/udp` | 公共层消费，不传给模块私有 view；`udp: false` 同时限制选路能力和实际 datagram open |
| `proxies` | 公开 type 为 `direct/reject/socks5/ss/vless/anytls`，其中 `reject/ss` 归一化为内部 `block/shadowsocks`；named direct/reject 默认启用 UDP，显式 `udp: false` 记录为禁用；只接受已实现的 TCP carrier |
| `proxy-groups` | 平面 `select`，只引用节点；嵌套组、自动选择和 dialer-proxy 不支持 |
| 基础规则 | DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、IP-CIDR、IP-CIDR6、SRC-IP-CIDR、SRC-PORT、DST-PORT、NETWORK、MATCH；域名 matcher 为 ASCII |
| 顶层三种端口 `0` | 禁用对应监听，image 不生成监听记录 |
| `listeners[].port` | 先弱转换为字符串再按十进制解析，quoted `'010'` 为 10、plain `010` 为 YAML 八进制 8；只接受 1–65535 单端口，零值临时端口和范围暂明确拒绝 |
| `listeners[].udp` | SOCKS/mixed 缺省为 true，显式 false 保留；HTTP 不接受 UDP 字段 |
| `listeners[].users` | 缺省继承全局 authentication；显式空数组不启用认证 |
| TLS | 记录已支持的 TLS/SNI 配置，默认 trust 由宿主 prepare 显式注入；拒绝 `certificate/private-key/ca-pem/skip-cert-verify`，不关闭验证 |
| SS UoT / AnyTLS 时间 | UoT 启用必须显式版本 2；AnyTLS 两个 idle 秒字段在缺省及 0–5 秒时归一为 30 秒，6–3600 秒按值转换为内部毫秒 |
| `dns/hosts/tun/sniffer`、Provider、Geo/RULE-SET | 未实现，明确拒绝 |
| YAML 解码的严格子集 | 不将小数端口截断为整数，不将标量上的 `!!seq/!!map` 回退为字符串，不接受非字符串 map key；与固定 Go YAML 的差异有独立样本 |

`config_differential_contract` 使用固定 mihomo 的 `go.yaml.in/yaml/v3 v3.0.5` 对 20 个解码子集样本做独立执行差分，登记上述 3 类刻意差异。
它验证解码接受/拒绝及 mode/端口/allow-lan 结果，不等于运行完整 mihomo 配置加载器。
`config_full_differential_contract` 进一步执行固定 mihomo 的原始 `UnmarshalRawConfig` → `ParseRawConfig`，
核对真实构造出的节点/组/监听/规则及有序 matcher；176/176 样本、8/8 外部资源防护通过。
测试不调用 ApplyConfig，不激活参考监听；macOS 使用禁网络沙箱，其他 OS 记录沙箱不可用并保留输入资源防护。
报告 `build/config-full-differential.json` 保留输入、双边实际结果、42 个刻意差异样本及理由、原始表示和源码校验信息。
完整构建与观察桥边界见 [差分说明](../../tests/support/config/reference/full/README.md)。这些旧格式结果不计为原生 `.conf` 通过，后续作为辅助/历史证据使用。

域名差异属于实际匹配行为：Solaris 按既有 ASCII 契约折叠 host 大小写，规范化规则前/尾点；
固定参考对大写 SOCKS host、DOMAIN 尾点和 DOMAIN-SUFFIX 前点可能选择不同规则。
双方真实 SOCKS 解码后的输入 host 尾点样本结果一致。生成 GLOBAL 仅含叶节点、显式 UDP gate、严格字段/范围校验、
UoT 显式 v2、数值 IPv6 bind 与 Vision UDP443 后缀也逐项登记，不宣称全量 mihomo 等价。

## 运行时与重载的已验证范围

公开 `runtime_proxy_contract` 及搬迁安装宿主覆盖 HTTP/CONNECT/WebSocket、SOCKS5 TCP/UDP、双 worker、
候选未开放业务、绑定失败、stale CAS、端口交换、旧 TCP/UDP 新地址族保活、认证/禁 UDP/移除、规则惰性 DNS 和 stop/restart。
`runtime_protocol_contract` 使用固定 sing-box v1.12.12，从 YAML 经公开 SDK 和真实入站验证 16 组配置：
六种 SS cipher 的 native UDP/UoT v2、VLESS plain/TLS + XUDP、AnyTLS、SOCKS5；每组覆盖两个 worker 的 TCP、IPv4/IPv6 UDP、公开 HTTP/HTTPS 测速和旧连接退休。
`runtime_control_contract` 验证接纳时固定控制视图、提交时迁移选择、握手/UDP 控制连接关闭、关闭后新流、准确逻辑计数、
测速取消/超时/跨提交/stop，以及日志 cursor/覆盖和销毁后的 owned 快照。物理流量只汇总 socket payload，
共享 session 无法准确拆分 USER/PROBE，物理值不可与逻辑值相加。
`runtime_advanced_contract` 补充 30 组 VLESS encryption/Vision/TLS/UDP443 和 16 组 SS AES EIH（1/2/8 层、native/UoT、多用户）
的 YAML → 公开 SDK → 真实入口 → 固定独立对端验证，含两 owner、HTTP(S) 测速、旧 UDP 跨 reload 新开 IPv6 lane。
固定 Xray 不返回空 XUDP 的行为有同对端独立客户端控制；两个 Python plain/TLS 对端另验证空 XUDP 正向路径。
一次 native/X25519/0-RTT 的 13 字节 UDP 超时尚未归因；相同短包/连续 reload 序列后续八轮及最终共享/静态验收通过，
不视为原因已解释。失败时新增的独立短包控制保留相同 peer、参数、target 和 payload，区分控制工具不支持与真实网络失败。
`runtime_acceptance_contract` 另补 WS/WSS 跨更新、UDP A/B/A 与反向首包、错误源/FRAG 和旧控制的新 admission；
`route_acceptance_contract` 使用真实 SDK/系统 resolver 加测试门闩与注入单调时钟，覆盖 DNS 排队、默认 300 秒 idle 和双 owner 准备失败。

宿主临时端口覆盖只作用于 image 中已有 listener ID，并返回 configured/requested/actual 地址。单个物理监听固定一个 worker，
不宣称单端口跨 worker 接纳。通配地址/具体地址的重叠绑定在线更改返回 ENOTSUP，需要停启。
prepared handle 不保活 I/O，stop/destroy 后仍可读取元数据；未提交候选在 stop 后失效。普通 TLS 不自动发现系统根证书。
